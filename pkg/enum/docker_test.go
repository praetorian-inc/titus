package enum

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
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
	enumerator.openFunc = imageFromBytesOpenFunc(t, imageArchive, "example/app:latest")

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
		switch {
		case strings.Contains(record.content, "CONFIG_TOKEN"):
			foundConfig = true
			ext, ok := record.prov.(types.ExtendedProvenance)
			require.True(t, ok, "metadata expected ExtendedProvenance, got %T", record.prov)
			assert.Equal(t, "docker", ext.Payload["source"])
			assert.Equal(t, "example/app:latest", ext.Payload["image"])
			assert.Equal(t, "metadata", ext.Payload["type"])
			assert.Equal(t, "docker://example/app:latest/config.json", ext.Payload["path"])
		case strings.Contains(record.content, "DOCKER_SECRET"):
			foundLayer = true
			arch, ok := record.prov.(types.ArchiveProvenance)
			require.True(t, ok, "layer file expected ArchiveProvenance, got %T", record.prov)
			assert.True(t, strings.HasPrefix(arch.ArchivePath, "docker://example/app:latest/sha256:"),
				"unexpected archive path: %s", arch.ArchivePath)
			assert.Equal(t, "app/config.env", arch.MemberPath)
		}
	}

	assert.True(t, foundConfig, "expected config JSON to be enumerated")
	assert.True(t, foundLayer, "expected layer file to be enumerated")
}

func TestDockerImageEnumeratorSkipsOversizedLayerFiles(t *testing.T) {
	imageArchive := buildDockerImageArchive(t, map[string][]byte{
		"small.txt": []byte("small"),
		"large.txt": []byte("this is larger than the configured limit"),
	})

	enumerator := NewDockerImageEnumerator("example/app:latest", Config{
		MaxFileSize: 10,
	})
	enumerator.openFunc = imageFromBytesOpenFunc(t, imageArchive, "example/app:latest")

	var contents []string
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		contents = append(contents, string(content))
		return nil
	})
	require.NoError(t, err)

	assert.Contains(t, contents, "small")
	for _, content := range contents {
		assert.NotContains(t, content, "larger than")
	}
}

// imageFromBytesOpenFunc returns an openFunc that loads a v1.Image from a
// docker-save tarball held entirely in memory. Used so tests don't depend on
// docker, a registry, or temp files.
func imageFromBytesOpenFunc(t *testing.T, archive []byte, expectedImage string) func(ctx context.Context, image string) (v1.Image, error) {
	t.Helper()
	return func(ctx context.Context, image string) (v1.Image, error) {
		require.Equal(t, expectedImage, image)
		tag, err := name.NewTag("titus-test:latest")
		require.NoError(t, err)
		return tarball.Image(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(archive)), nil
		}, &tag)
	}
}

func TestDockerImageEnumeratorMultipleLayersConcurrent(t *testing.T) {
	layers := []map[string][]byte{
		{"layer1/file1.env": []byte("SECRET_ONE=AKIATESTKEY1111111111\n")},
		{"layer2/file2.env": []byte("SECRET_TWO=AKIATESTKEY2222222222\n")},
		{"layer3/file3.env": []byte("SECRET_THREE=AKIATESTKEY3333333333\n")},
		{"layer4/file4.env": []byte("SECRET_FOUR=AKIATESTKEY4444444444\n")},
	}
	archive := buildMultiLayerDockerImageArchive(t, layers)

	enumerator := NewDockerImageEnumerator("example/multi:latest", Config{
		MaxFileSize: 10 * 1024 * 1024,
		NumReaders:  4,
	})
	enumerator.openFunc = imageFromBytesOpenFunc(t, archive, "example/multi:latest")

	var mu sync.Mutex
	contents := make(map[string]bool)
	err := enumerator.Enumerate(context.Background(), func(content []byte, blobID types.BlobID, prov types.Provenance) error {
		mu.Lock()
		contents[string(content)] = true
		mu.Unlock()
		return nil
	})
	require.NoError(t, err)

	for _, layer := range layers {
		for _, content := range layer {
			assert.True(t, contents[string(content)], "missing content emitted from layer: %s", content)
		}
	}
}

func buildMultiLayerDockerImageArchive(t *testing.T, layers []map[string][]byte) []byte {
	t.Helper()

	layerNames := make([]string, len(layers))
	diffIDs := make([]string, len(layers))
	files := map[string][]byte{}
	for i, layerFiles := range layers {
		layerTar := buildTar(t, layerFiles)
		sum := sha256.Sum256(layerTar)
		diffIDs[i] = "sha256:" + hex.EncodeToString(sum[:])
		layerNames[i] = fmt.Sprintf("layer%d/layer.tar", i)
		files[layerNames[i]] = layerTar
	}

	diffIDsJSON := `"` + strings.Join(diffIDs, `","`) + `"`
	layerNamesJSON := `"` + strings.Join(layerNames, `","`) + `"`

	files["config.json"] = fmt.Appendf(nil,
		`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[%s]}}`,
		diffIDsJSON,
	)
	files["manifest.json"] = fmt.Appendf(nil,
		`[{"Config":"config.json","RepoTags":["titus-test:latest"],"Layers":[%s]}]`,
		layerNamesJSON,
	)

	return buildTar(t, files)
}

func buildDockerImageArchive(t *testing.T, layerFiles map[string][]byte) []byte {
	t.Helper()

	layer := buildTar(t, layerFiles)
	sum := sha256.Sum256(layer)
	diffID := "sha256:" + hex.EncodeToString(sum[:])

	config := fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","config":{"Env":["CONFIG_TOKEN=AKIATESTKEY1234567890"]},"rootfs":{"type":"layers","diff_ids":[%q]}}`,
		diffID,
	)

	return buildTar(t, map[string][]byte{
		"manifest.json":   []byte(`[{"Config":"config.json","RepoTags":["titus-test:latest"],"Layers":["layer/layer.tar"]}]`),
		"config.json":     []byte(config),
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
