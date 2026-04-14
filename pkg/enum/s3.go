package enum

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/praetorian-inc/titus/pkg/types"
)

// S3Enumerator enumerates objects from an S3 bucket.
type S3Enumerator struct {
	Bucket string
	Prefix string
	config Config
	client *s3.Client
}

// NewS3Enumerator creates a new S3 enumerator for the given bucket and prefix.
func NewS3Enumerator(bucket, prefix string, config Config) *S3Enumerator {
	return &S3Enumerator{
		Bucket: bucket,
		Prefix: prefix,
		config: config,
	}
}

// Enumerate lists objects in the S3 bucket and yields their content.
func (e *S3Enumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	// Initialize AWS SDK client
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	e.client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		// Suppress checksum validation warnings for objects without checksums
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})

	// List objects with pagination
	paginator := s3.NewListObjectsV2Paginator(e.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(e.Bucket),
		Prefix: aws.String(e.Prefix),
	})

	for paginator.HasMorePages() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing S3 objects: %w", err)
		}

		for _, obj := range page.Contents {
			if err := e.processObject(ctx, obj, callback); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Log warning but continue scanning other objects
				fmt.Fprintf(os.Stderr, "[warn] S3 object %s: %v\n", aws.ToString(obj.Key), err)
			}
		}
	}

	return nil
}

// processObject downloads and processes a single S3 object.
func (e *S3Enumerator) processObject(ctx context.Context, obj s3types.Object, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	key := aws.ToString(obj.Key)

	// Skip directories (keys ending in /)
	if strings.HasSuffix(key, "/") {
		return nil
	}

	// Skip objects exceeding max file size
	if e.config.MaxFileSize > 0 && aws.ToInt64(obj.Size) > e.config.MaxFileSize {
		return nil
	}

	// Download object
	resp, err := e.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(e.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("getting object: %w", err)
	}
	defer resp.Body.Close()

	// Read with size limit to prevent OOM
	maxRead := e.config.MaxFileSize
	if maxRead <= 0 {
		maxRead = 100 * 1024 * 1024 // 100MB default cap
	}
	limited := io.LimitReader(resp.Body, maxRead+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("reading object body: %w", err)
	}
	if int64(len(content)) > maxRead {
		return nil // Skip oversized objects
	}

	s3Path := fmt.Sprintf("s3://%s/%s", e.Bucket, key)

	binary := isBinary(content)

	// Handle binary files with extraction enabled
	if binary && e.config.ExtractArchives != "" {
		ext := getExtension(key)
		if shouldExtract(e.config, ext) {
			extracted, err := ExtractText(key, content, e.config.ExtractLimits)
			if err == nil && len(extracted) > 0 {
				for _, ec := range extracted {
					blobID := types.ComputeBlobID(ec.Content)
					prov := types.ArchiveProvenance{
						ArchivePath: s3Path,
						MemberPath:  ec.Name,
					}
					if err := callback(ec.Content, blobID, prov); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}

	if binary {
		return nil
	}

	blobID := types.ComputeBlobID(content)
	prov := types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source": "s3",
			"bucket": e.Bucket,
			"key":    key,
			"path":   s3Path,
		},
	}

	return callback(content, blobID, prov)
}

// ParseS3URL parses an s3://bucket/prefix URL into bucket and prefix components.
func ParseS3URL(rawURL string) (bucket, prefix string, ok bool) {
	if !strings.HasPrefix(rawURL, "s3://") {
		return "", "", false
	}
	path := strings.TrimPrefix(rawURL, "s3://")
	parts := strings.SplitN(path, "/", 2)
	bucket = parts[0]
	if bucket == "" {
		return "", "", false
	}
	if len(parts) > 1 {
		prefix = parts[1]
	}
	return bucket, prefix, true
}
