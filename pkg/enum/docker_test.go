package enum

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDockerImageReference(t *testing.T) {
	image, ok := ParseDockerImageReference("docker://alpine:latest")
	require.True(t, ok)
	assert.Equal(t, "alpine:latest", image)

	_, ok = ParseDockerImageReference("alpine:latest")
	assert.False(t, ok)

	_, ok = ParseDockerImageReference("docker://")
	assert.False(t, ok)
}

func TestDockerImageEnumeratorEnumeratesMetadataAndLayerFiles(t *testing.T) {
	imageArchive := buildDockerImageArchive(t, map[string][]byte{
		"app/config.env": []byte("DOCKER_SECRET=AKIATESTKEY1234567890\n"),
	})

	enumerator := NewDockerImageEnumerator("example/app:latest", Config{
		MaxFileSize: 10 * 1024 * 1024,
	})
	enumerator.saveFunc = func(ctx context.Context, image string) (io.ReadCloser, error) {
		require.Equal(t, "example/app:latest", image)
		return io.NopCloser(bytes.NewReader(imageArchive)), nil
	}

	type callbackRecord struct {
		content string
		prov    types.Provenance
	}
	var records []callbackRecord
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		records = append(records, callbackRecord{content: string(content), prov: prov})
		require.Equal(t, types.ComputeBlobID(content), blobID)
		return nil
	})
	require.NoError(t, err)

	var foundConfig bool
	var foundLayer bool
	for _, record := range records {
		ext, ok := record.prov.(types.ExtendedProvenance)
		require.True(t, ok, "expected ExtendedProvenance, got %T", record.prov)
		assert.Equal(t, "docker", ext.Payload["source"])
		assert.Equal(t, "example/app:latest", ext.Payload["image"])

		if strings.Contains(record.content, "CONFIG_TOKEN") {
			foundConfig = true
			assert.Equal(t, "metadata", ext.Payload["type"])
			assert.Equal(t, "docker://example/app:latest/config.json", ext.Payload["path"])
		}
		if strings.Contains(record.content, "DOCKER_SECRET") {
			foundLayer = true
			assert.Equal(t, "layer", ext.Payload["type"])
			assert.Equal(t, "layer/layer.tar", ext.Payload["layer"])
			assert.Equal(t, "docker://example/app:latest/layer/layer.tar:app/config.env", ext.Payload["path"])
		}
	}

	assert.True(t, foundConfig, "expected config JSON to be enumerated")
	assert.True(t, foundLayer, "expected layer file to be enumerated")
}

func TestDockerImageEnumeratorEnumeratesOCILayoutBlobs(t *testing.T) {
	layer := gzipContent(t, buildTar(t, map[string][]byte{
		"etc/service.env": []byte("OCI_SECRET=AKIATESTKEY1234567890\n"),
	}))
	imageArchive := buildTar(t, map[string][]byte{
		"blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": []byte(`{"config":{"Env":["OCI_CONFIG_TOKEN=AKIATESTKEY1234567890"]}}`),
		"blobs/sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": layer,
		"index.json": []byte(`{"schemaVersion":2}`),
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`),
	})

	enumerator := NewDockerImageEnumerator("example/oci:latest", Config{
		MaxFileSize: 10 * 1024 * 1024,
	})
	enumerator.saveFunc = func(ctx context.Context, image string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(imageArchive)), nil
	}

	var paths []string
	var contents []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		contents = append(contents, string(content))
		paths = append(paths, prov.Path())
		return nil
	})
	require.NoError(t, err)

	assert.Contains(t, contents, `{"config":{"Env":["OCI_CONFIG_TOKEN=AKIATESTKEY1234567890"]}}`)
	assert.Contains(t, contents, "OCI_SECRET=AKIATESTKEY1234567890\n")
	assert.Contains(t, paths, "docker://example/oci:latest/blobs/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	assert.Contains(t, paths, "docker://example/oci:latest/blobs/sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:etc/service.env")
}

func TestDockerImageEnumeratorSkipsOversizedLayerFiles(t *testing.T) {
	imageArchive := buildDockerImageArchive(t, map[string][]byte{
		"small.txt": []byte("small"),
		"large.txt": []byte("this is larger than the configured limit"),
	})

	enumerator := NewDockerImageEnumerator("example/app:latest", Config{
		MaxFileSize: 10,
	})
	enumerator.saveFunc = func(ctx context.Context, image string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(imageArchive)), nil
	}

	var contents []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		contents = append(contents, string(content))
		return nil
	})
	require.NoError(t, err)

	assert.Contains(t, contents, "small")
	for _, content := range contents {
		assert.NotContains(t, content, "larger than")
		assert.NotContains(t, content, "CONFIG_TOKEN")
	}
}

func buildDockerImageArchive(t *testing.T, layerFiles map[string][]byte) []byte {
	t.Helper()

	layer := buildTar(t, layerFiles)

	return buildTar(t, map[string][]byte{
		"manifest.json":   []byte(`[{"Config":"config.json","Layers":["layer/layer.tar"]}]`),
		"config.json":     []byte(`{"config":{"Env":["CONFIG_TOKEN=AKIATESTKEY1234567890"]}}`),
		"layer/layer.tar": layer,
	})
}

func buildTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		})
		require.NoError(t, err)
		_, err = tw.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func gzipContent(t *testing.T, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(content)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}
