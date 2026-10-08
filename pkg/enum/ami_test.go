package enum

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const amiExampleSecret = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func TestParseAMIReference(t *testing.T) {
	id := "ami-0123456789abcdef0"
	parsed, ok := ParseAMIReference("ami://" + id)
	require.True(t, ok)
	assert.Equal(t, id, parsed.ImageID)
	assert.Empty(t, parsed.Region)

	parsed, ok = ParseAMIReference("ami://us-west-2/" + id + "/")
	require.True(t, ok)
	assert.Equal(t, id, parsed.ImageID)
	assert.Equal(t, "us-west-2", parsed.Region)

	parsed, ok = ParseAMIReference("AMI://US-EAST-1/AMI-ABCDE123")
	require.True(t, ok)
	assert.Equal(t, "ami-abcde123", parsed.ImageID)
	assert.Equal(t, "us-east-1", parsed.Region)

	for _, raw := range []string{"", "ami://", "ami://not-an-ami", "docker://ami-0123456789abcdef0", "ami://us-east-1/ami-short", "ami://region/ami-0123456789abcdef0"} {
		_, ok = ParseAMIReference(raw)
		assert.Falsef(t, ok, "expected %q to be rejected", raw)
	}
}

func TestAMITargetFromFlag(t *testing.T) {
	id := "ami-0123456789abcdef0"
	parsed, err := AMITargetFromFlag(id)
	require.NoError(t, err)
	assert.Equal(t, id, parsed.ImageID)

	parsed, err = AMITargetFromFlag("./disk.raw")
	require.NoError(t, err)
	assert.Equal(t, "./disk.raw", parsed.Path)
	assert.Empty(t, parsed.ImageID)

	_, err = AMITargetFromFlag("  ")
	require.Error(t, err)
}

func TestEBSVolumeSpecs(t *testing.T) {
	img := ec2types.Image{
		RootDeviceName: aws.String("/dev/xvda"),
		RootDeviceType: ec2types.DeviceTypeEbs,
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{
			{DeviceName: aws.String("/dev/sdf"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-data")}},
			{DeviceName: aws.String("/dev/xvda"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-root")}},
			{DeviceName: aws.String("ephemeral0"), VirtualName: aws.String("ephemeral0")},
			{DeviceName: aws.String("/dev/sdf"), Ebs: &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-data")}},
		},
	}
	specs, err := ebsVolumeSpecs(img, "ami-0123456789abcdef0")
	require.NoError(t, err)
	require.Len(t, specs, 2)
	assert.Equal(t, "snap-root", specs[0].SnapshotID)
	assert.Equal(t, "snap-data", specs[1].SnapshotID)

	_, err = ebsVolumeSpecs(ec2types.Image{RootDeviceType: ec2types.DeviceTypeInstanceStore}, "ami-0123456789abcdef0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "instance-store")

	_, err = ebsVolumeSpecs(ec2types.Image{RootDeviceType: ec2types.DeviceTypeEbs}, "ami-0123456789abcdef0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no EBS snapshots")
}

func TestWrapSnapshotReadErrorAccessDenied(t *testing.T) {
	err := wrapSnapshotReadError("snap-1", smithyCodeError{code: "AccessDeniedException", msg: "nope"})
	assert.ErrorContains(t, err, "snap-1")
	assert.ErrorContains(t, err, "copy the AMI")
}

func TestSnapshotReaderHolesChecksumAndRefresh(t *testing.T) {
	block := bytes.Repeat([]byte{0xab}, 512)
	sum := sha256.Sum256(block)
	api := &fakeEBS{
		blockSize: 512,
		volumeGiB: 1,
		blocks:    map[int32][]byte{0: block, 2: bytes.Repeat([]byte{0xcd}, 512)},
		checksum:  base64.StdEncoding.EncodeToString(sum[:]),
		pageSize:  1,
	}
	reader, err := newSnapshotReader(context.Background(), api, "snap-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1<<30), reader.Size())
	assert.GreaterOrEqual(t, api.listCalls, 2, "block index list should paginate")

	got := make([]byte, 512)
	_, err = reader.ReadAt(got, 0)
	require.NoError(t, err)
	assert.Equal(t, block, got)

	hole := make([]byte, 512)
	_, err = reader.ReadAt(hole, 512)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, 512), hole)

	// Block 2 has different bytes, so the shared checksum fails and must not be returned.
	_, err = reader.ReadAt(got, 1024)
	require.Error(t, err)
	assert.ErrorContains(t, err, "checksum")

	stale := &fakeEBS{
		blockSize: 512,
		volumeGiB: 1,
		blocks:    map[int32][]byte{0: block},
		failGets:  1,
		failCode:  "ValidationException",
	}
	reader, err = newSnapshotReader(context.Background(), stale, "snap-stale")
	require.NoError(t, err)
	_, err = reader.ReadAt(got, 0)
	require.NoError(t, err)
	assert.Equal(t, block, got)
	assert.GreaterOrEqual(t, stale.listCalls, 2, "expired block token should re-list")
}

func TestAMIEnumeratorLocalExt4(t *testing.T) {
	path := filepath.Join("testdata", "ami", "secret.ext4")
	e := NewAMIEnumerator(AMITarget{Path: path}, "", Config{MaxFileSize: 1024 * 1024})
	got := collectAMI(t, e)
	require.True(t, mapContains(got, amiExampleSecret), "emitted files: %v", keysOf(got))
	for path, content := range got {
		assert.NotContains(t, path, "package-lock.json")
		assert.NotContains(t, path, "libtest.so")
		assert.Contains(t, path, "ami://")
		if strings.HasSuffix(path, "etc/secret.txt") {
			assert.Equal(t, amiExampleSecret+"\n", content)
		}
	}
}

func TestAMIEnumeratorPartitionedExt4(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ami", "secret.ext4"))
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		disk []byte
	}{
		{"gpt", wrapGPT(raw)},
		{"mbr", wrapMBR(raw)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vol := amiVolume{Label: "ami://disk", Disk: bytes.NewReader(tc.disk), Size: int64(len(tc.disk))}
			var secret string
			n, notes, err := scanAMIDisk(context.Background(), vol, Config{MaxFileSize: 1024 * 1024}, nil, func(content []byte, _ types.BlobID, prov types.Provenance) error {
				if strings.Contains(string(content), amiExampleSecret) {
					secret = prov.Path()
				}
				return nil
			})
			require.NoError(t, err, "notes: %v", notes)
			assert.Greater(t, n, 0)
			assert.Contains(t, secret, "etc/secret.txt")
		})
	}
}

func TestAMIEnumeratorXFS(t *testing.T) {
	path := filepath.Join("testdata", "ami", "secret.xfs")
	e := NewAMIEnumerator(AMITarget{Path: path}, "", Config{MaxFileSize: 1024 * 1024})
	got := collectAMI(t, e)
	var found bool
	for path, content := range got {
		if strings.Contains(content, "AKIAIOSFODNN7EXAMPLE") {
			found = true
			assert.Contains(t, path, "etc/xfs-secret.txt")
		}
	}
	require.True(t, found, "xfs secret was not emitted: %v", keysOf(got))
}

func TestAMIEnumeratorRemoteSnapshot(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ami", "secret.ext4"))
	require.NoError(t, err)
	const blockSize = 512 * 1024
	blocks := map[int32][]byte{}
	for off := 0; off < len(raw); off += blockSize {
		end := min(off+blockSize, len(raw))
		chunk := make([]byte, blockSize)
		copy(chunk, raw[off:end])
		blocks[int32(off/blockSize)] = chunk
	}
	images := fakeImages{img: ec2types.Image{
		ImageId:        aws.String("ami-0123456789abcdef0"),
		State:          ec2types.ImageStateAvailable,
		RootDeviceName: aws.String("/dev/xvda"),
		RootDeviceType: ec2types.DeviceTypeEbs,
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{
			DeviceName: aws.String("/dev/xvda"),
			Ebs:        &ec2types.EbsBlockDevice{SnapshotId: aws.String("snap-root")},
		}},
	}}
	snaps := &fakeEBS{blockSize: blockSize, volumeGiB: 1, blocks: blocks}
	e := NewAMIEnumerator(AMITarget{ImageID: "ami-0123456789abcdef0", Region: "us-east-1"}, "us-west-2", Config{MaxFileSize: 1024 * 1024})
	e.clients = func(_ context.Context, region string) (*amiClients, error) {
		assert.Equal(t, "us-east-1", region, "URL region must beat --region")
		return &amiClients{images: images, snapshots: snaps, region: region}, nil
	}

	var secretPath string
	err = e.Enumerate(context.Background(), func(content []byte, id types.BlobID, prov types.Provenance) error {
		assert.Equal(t, types.ComputeBlobID(content), id)
		if strings.Contains(string(content), amiExampleSecret) {
			secretPath = prov.Path()
			ext, ok := prov.(types.ExtendedProvenance)
			require.True(t, ok)
			assert.Equal(t, "ami", ext.Payload["source"])
			assert.Equal(t, "snap-root", ext.Payload["snapshot"])
			assert.Equal(t, "/dev/xvda", ext.Payload["device"])
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, "ami://us-east-1/ami-0123456789abcdef0/dev/xvda/etc/secret.txt", secretPath)
}

type emitMap map[string]string

func collectAMI(t *testing.T, e *AMIEnumerator) emitMap {
	t.Helper()
	got := emitMap{}
	err := e.Enumerate(context.Background(), func(content []byte, id types.BlobID, prov types.Provenance) error {
		assert.Equal(t, types.ComputeBlobID(content), id)
		got[prov.Path()] = string(content)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, got)
	return got
}

func mapContains(m emitMap, substr string) bool {
	for _, content := range m {
		if strings.Contains(content, substr) {
			return true
		}
	}
	return false
}

func keysOf(m emitMap) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func wrapGPT(fsImage []byte) []byte {
	const sector = 512
	const partStart = 2048
	partSectors := (len(fsImage) + sector - 1) / sector
	totalSectors := partStart + partSectors
	disk := make([]byte, totalSectors*sector)
	copy(disk[partStart*sector:], fsImage)

	disk[446+4] = 0xEE
	binary.LittleEndian.PutUint32(disk[446+8:], 1)
	binary.LittleEndian.PutUint32(disk[446+12:], uint32(totalSectors-1))
	disk[510] = 0x55
	disk[511] = 0xAA

	header := disk[sector : sector+92]
	copy(header[:8], gptSignature)
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], 92)
	binary.LittleEndian.PutUint64(header[24:32], 1)
	binary.LittleEndian.PutUint64(header[32:40], uint64(totalSectors-1))
	binary.LittleEndian.PutUint64(header[40:48], 34)
	binary.LittleEndian.PutUint64(header[48:56], uint64(totalSectors-34))
	header[56] = 1
	binary.LittleEndian.PutUint64(header[72:80], 2)
	binary.LittleEndian.PutUint32(header[80:84], 128)
	binary.LittleEndian.PutUint32(header[84:88], 128)

	ent := disk[2*sector : 2*sector+128]
	copy(ent[:16], []byte{
		0xAF, 0x3D, 0xC6, 0x0F,
		0x83, 0x84,
		0x72, 0x47,
		0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
	})
	ent[16] = 2
	binary.LittleEndian.PutUint64(ent[32:40], partStart)
	binary.LittleEndian.PutUint64(ent[40:48], uint64(partStart+partSectors-1))
	for i, c := range utf16.Encode([]rune("root")) {
		binary.LittleEndian.PutUint16(ent[56+i*2:], c)
	}
	array := disk[2*sector : 2*sector+128*128]
	binary.LittleEndian.PutUint32(header[88:92], crc32.ChecksumIEEE(array))
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:92]))
	return disk
}

func wrapMBR(fsImage []byte) []byte {
	const sector = 512
	const partStart = 2048
	partSectors := (len(fsImage) + sector - 1) / sector
	disk := make([]byte, (partStart+partSectors)*sector)
	copy(disk[partStart*sector:], fsImage)
	disk[446+4] = 0x83
	binary.LittleEndian.PutUint32(disk[446+8:], partStart)
	binary.LittleEndian.PutUint32(disk[446+12:], uint32(partSectors))
	disk[510] = 0x55
	disk[511] = 0xAA
	return disk
}

type fakeImages struct {
	img ec2types.Image
}

func (f fakeImages) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return &ec2.DescribeImagesOutput{Images: []ec2types.Image{f.img}}, nil
}

type fakeEBS struct {
	mu        sync.Mutex
	blockSize int32
	volumeGiB int64
	blocks    map[int32][]byte
	checksum  string
	pageSize  int
	failGets  int
	failCode  string
	listCalls int
	getCalls  int
}

func (f *fakeEBS) ListSnapshotBlocks(_ context.Context, params *ebs.ListSnapshotBlocksInput, _ ...func(*ebs.Options)) (*ebs.ListSnapshotBlocksOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	idxs := make([]int32, 0, len(f.blocks))
	for idx := range f.blocks {
		idxs = append(idxs, idx)
	}
	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })
	start := 0
	if params.NextToken != nil && *params.NextToken != "" {
		if n, err := strconv.Atoi(*params.NextToken); err == nil {
			start = n
		}
	}
	end := len(idxs)
	var next *string
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
		s := strconv.Itoa(end)
		next = &s
	}
	out := make([]ebstypes.Block, 0, end-start)
	for _, idx := range idxs[start:end] {
		i := idx
		tok := "tok-" + strconv.Itoa(int(i))
		out = append(out, ebstypes.Block{BlockIndex: &i, BlockToken: &tok})
	}
	bs, vs := f.blockSize, f.volumeGiB
	return &ebs.ListSnapshotBlocksOutput{Blocks: out, BlockSize: &bs, VolumeSize: &vs, NextToken: next}, nil
}

func (f *fakeEBS) GetSnapshotBlock(_ context.Context, params *ebs.GetSnapshotBlockInput, _ ...func(*ebs.Options)) (*ebs.GetSnapshotBlockOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.failGets > 0 {
		f.failGets--
		return nil, smithyCodeError{code: f.failCode, msg: f.failCode}
	}
	idx := aws.ToInt32(params.BlockIndex)
	data := append([]byte(nil), f.blocks[idx]...)
	sum := f.checksum
	if sum == "" && data != nil {
		digest := sha256.Sum256(data)
		sum = base64.StdEncoding.EncodeToString(digest[:])
	}
	n := int32(len(data))
	return &ebs.GetSnapshotBlockOutput{
		BlockData:         ioNopCloser{bytes.NewReader(data)},
		Checksum:          &sum,
		ChecksumAlgorithm: ebstypes.ChecksumAlgorithmChecksumAlgorithmSha256,
		DataLength:        &n,
	}, nil
}

type ioNopCloser struct{ *bytes.Reader }

func (ioNopCloser) Close() error { return nil }

type smithyCodeError struct{ code, msg string }

func (e smithyCodeError) Error() string                 { return e.msg }
func (e smithyCodeError) ErrorCode() string             { return e.code }
func (e smithyCodeError) ErrorMessage() string          { return e.msg }
func (e smithyCodeError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }
