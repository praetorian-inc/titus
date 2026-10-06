package enum

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"github.com/aws/smithy-go"
)

const (
	snapshotListPage     = 10000
	snapshotMaxBlockSize = 1024 * 1024
	snapshotMinBlockSize = 512
	snapshotMaxVolumeGiB = 256 * 1024
	snapshotCacheBlocks  = 64
	snapshotFetchTries   = 5
)

// snapshotBlockAPI is the EBS direct API surface used to read a snapshot.
type snapshotBlockAPI interface {
	ListSnapshotBlocks(ctx context.Context, params *ebs.ListSnapshotBlocksInput, optFns ...func(*ebs.Options)) (*ebs.ListSnapshotBlocksOutput, error)
	GetSnapshotBlock(ctx context.Context, params *ebs.GetSnapshotBlockInput, optFns ...func(*ebs.Options)) (*ebs.GetSnapshotBlockOutput, error)
}

// snapshotReader is an io.ReaderAt over an EBS snapshot. Unallocated blocks
// read as zeros. Allocated blocks are fetched on demand and cached.
// ReadAt is safe for concurrent callers; the filesystem walk itself is single-threaded.
type snapshotReader struct {
	mu         sync.Mutex
	ctx        context.Context
	api        snapshotBlockAPI
	snapshotID string
	blockSize  int
	size       int64
	tokens     map[int32]string
	expiry     time.Time
	cache      *blockCache
	zeros      []byte
}

func newSnapshotReader(ctx context.Context, api snapshotBlockAPI, snapshotID string) (*snapshotReader, error) {
	if snapshotID == "" {
		return nil, fmt.Errorf("snapshot ID is required")
	}
	r := &snapshotReader{
		ctx:        ctx,
		api:        api,
		snapshotID: snapshotID,
		cache:      newBlockCache(snapshotCacheBlocks),
	}
	if err := r.reload(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Size is the volume size in bytes.
func (r *snapshotReader) Size() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// ReadAt implements io.ReaderAt.
func (r *snapshotReader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fmt.Errorf("negative snapshot offset %d", off)
	}
	if off >= r.size {
		return 0, io.EOF
	}
	wantEOF := false
	if off+int64(len(p)) > r.size {
		p = p[:r.size-off]
		wantEOF = true
	}
	n := 0
	for len(p) > 0 {
		idx := int32(off / int64(r.blockSize))
		blockOff := int(off % int64(r.blockSize))
		block, err := r.block(idx)
		if err != nil {
			if n > 0 {
				return n, err
			}
			return 0, err
		}
		copied := copy(p, block[blockOff:])
		n += copied
		p = p[copied:]
		off += int64(copied)
	}
	if wantEOF {
		return n, io.EOF
	}
	return n, nil
}

func (r *snapshotReader) block(idx int32) ([]byte, error) {
	if data, ok := r.cache.get(idx); ok {
		return data, nil
	}
	if err := r.ensureFresh(); err != nil {
		return nil, err
	}
	token, ok := r.tokens[idx]
	if !ok {
		return r.zero(), nil
	}
	data, err := r.fetch(idx, token)
	if err != nil && snapshotTokenStale(err) {
		if rerr := r.reload(r.ctx); rerr != nil {
			return nil, rerr
		}
		token, ok = r.tokens[idx]
		if !ok {
			return r.zero(), nil
		}
		data, err = r.fetch(idx, token)
	}
	if err != nil {
		return nil, err
	}
	r.cache.put(idx, data)
	return data, nil
}

func (r *snapshotReader) zero() []byte {
	if r.zeros == nil {
		r.zeros = make([]byte, r.blockSize)
	}
	return r.zeros
}

func (r *snapshotReader) ensureFresh() error {
	if r.expiry.IsZero() || time.Now().Before(r.expiry.Add(-time.Minute)) {
		return nil
	}
	return r.reload(r.ctx)
}

func (r *snapshotReader) reload(ctx context.Context) error {
	tokens, blockSize, volumeGiB, expiry, err := listSnapshotBlocks(ctx, r.api, r.snapshotID)
	if err != nil {
		return err
	}
	r.tokens = tokens
	r.blockSize = blockSize
	r.size = volumeGiB * 1024 * 1024 * 1024
	r.expiry = expiry
	r.zeros = nil
	r.cache.clear()
	return nil
}

func (r *snapshotReader) fetch(idx int32, token string) ([]byte, error) {
	var last error
	for attempt := range snapshotFetchTries {
		if attempt > 0 {
			if err := sleepCtx(r.ctx, time.Duration(attempt)*200*time.Millisecond); err != nil {
				return nil, err
			}
		}
		data, err := r.fetchOnce(idx, token)
		if err == nil || !retryableSnapshotErr(err) {
			return data, err
		}
		last = err
	}
	return nil, last
}

func (r *snapshotReader) fetchOnce(idx int32, token string) ([]byte, error) {
	out, err := r.api.GetSnapshotBlock(r.ctx, &ebs.GetSnapshotBlockInput{
		SnapshotId: aws.String(r.snapshotID),
		BlockIndex: aws.Int32(idx),
		BlockToken: aws.String(token),
	})
	if err != nil {
		return nil, err
	}
	if out == nil || out.BlockData == nil {
		return nil, fmt.Errorf("snapshot %s block %d returned no data", r.snapshotID, idx)
	}
	defer out.BlockData.Close()
	data, err := io.ReadAll(out.BlockData)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot %s block %d: %w", r.snapshotID, idx, err)
	}
	if len(data) != r.blockSize {
		return nil, fmt.Errorf("snapshot %s block %d is %d bytes, want %d", r.snapshotID, idx, len(data), r.blockSize)
	}
	if out.DataLength != nil && int(*out.DataLength) != len(data) {
		return nil, fmt.Errorf("snapshot %s block %d length %d does not match body", r.snapshotID, idx, *out.DataLength)
	}
	if err := verifyBlockChecksum(data, aws.ToString(out.Checksum), out.ChecksumAlgorithm); err != nil {
		return nil, fmt.Errorf("snapshot %s block %d: %w", r.snapshotID, idx, err)
	}
	return data, nil
}

func listSnapshotBlocks(ctx context.Context, api snapshotBlockAPI, snapshotID string) (map[int32]string, int, int64, time.Time, error) {
	tokens := make(map[int32]string)
	var blockSize int32
	var volumeGiB int64
	var expiry time.Time
	var next *string
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, 0, time.Time{}, err
		}
		out, err := api.ListSnapshotBlocks(ctx, &ebs.ListSnapshotBlocksInput{
			SnapshotId: aws.String(snapshotID),
			MaxResults: aws.Int32(snapshotListPage),
			NextToken:  next,
		})
		if err != nil {
			return nil, 0, 0, time.Time{}, fmt.Errorf("listing blocks of snapshot %s: %w", snapshotID, err)
		}
		if out.BlockSize != nil {
			blockSize = *out.BlockSize
		}
		if out.VolumeSize != nil {
			volumeGiB = *out.VolumeSize
		}
		if out.ExpiryTime != nil {
			expiry = *out.ExpiryTime
		}
		for _, block := range out.Blocks {
			if block.BlockIndex == nil || block.BlockToken == nil || *block.BlockToken == "" {
				continue
			}
			tokens[*block.BlockIndex] = *block.BlockToken
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	if blockSize < snapshotMinBlockSize || blockSize > snapshotMaxBlockSize {
		return nil, 0, 0, time.Time{}, fmt.Errorf("snapshot %s has unsupported block size %d", snapshotID, blockSize)
	}
	if volumeGiB <= 0 || volumeGiB > snapshotMaxVolumeGiB {
		return nil, 0, 0, time.Time{}, fmt.Errorf("snapshot %s has implausible volume size %d GiB", snapshotID, volumeGiB)
	}
	return tokens, int(blockSize), volumeGiB, expiry, nil
}

func verifyBlockChecksum(data []byte, sum string, algo ebstypes.ChecksumAlgorithm) error {
	if sum == "" {
		return nil
	}
	if algo != "" && algo != ebstypes.ChecksumAlgorithmChecksumAlgorithmSha256 {
		return fmt.Errorf("unsupported checksum algorithm %s", algo)
	}
	digest := sha256.Sum256(data)
	got := base64.StdEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(sum)) != 1 {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}

func retryableSnapshotErr(err error) bool {
	var apiErr smithy.APIError
	if !asSmithyAPIError(err, &apiErr) {
		return errors.Is(err, io.ErrUnexpectedEOF)
	}
	switch apiErr.ErrorCode() {
	case "RequestThrottledException", "ThrottlingException", "RequestTimeout", "ServiceUnavailableException", "InternalServerException", "SlowDown":
		return true
	default:
		return false
	}
}

func snapshotTokenStale(err error) bool {
	var apiErr smithy.APIError
	if !asSmithyAPIError(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "ValidationException", "InvalidBlockToken", "ExpiredTokenException":
		return true
	default:
		return false
	}
}

func asSmithyAPIError(err error, target *smithy.APIError) bool {
	if err == nil || target == nil {
		return false
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	*target = apiErr
	return true
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type blockCache struct {
	cap   int
	order []int32
	data  map[int32][]byte
}

func newBlockCache(cap int) *blockCache {
	if cap < 1 {
		cap = 1
	}
	return &blockCache{cap: cap, data: make(map[int32][]byte)}
}

func (c *blockCache) get(idx int32) ([]byte, bool) {
	data, ok := c.data[idx]
	return data, ok
}

func (c *blockCache) put(idx int32, data []byte) {
	if _, ok := c.data[idx]; ok {
		c.data[idx] = data
		return
	}
	if len(c.order) >= c.cap {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.data, old)
	}
	c.order = append(c.order, idx)
	c.data[idx] = data
}

func (c *blockCache) clear() {
	c.order = c.order[:0]
	c.data = make(map[int32][]byte)
}
