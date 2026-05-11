package enum

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/praetorian-inc/titus/pkg/types"
)

// DockerImageEnumerator enumerates scan blobs from a Docker / OCI image.
type DockerImageEnumerator struct {
	Image string

	config   Config
	openFunc func(ctx context.Context, image string) (v1.Image, error)
}

// NewDockerImageEnumerator creates an enumerator for a Docker / OCI image
// reference. The reference may be a registry ref (alpine:latest,
// ghcr.io/foo/bar:v1), a path to a docker-save tarball, or a path to an OCI
// image layout directory.
func NewDockerImageEnumerator(image string, config Config) *DockerImageEnumerator {
	if parsed, ok := ParseDockerImageReference(image); ok {
		image = parsed
	}
	return &DockerImageEnumerator{
		Image:    image,
		config:   config,
		openFunc: openImage,
	}
}

// Enumerate fetches the image (registry pull / local tarball / OCI layout),
// emits the manifest and config blobs as metadata, and scans every regular
// file in every layer. Files deleted by later layers are intentionally
// included because secrets can remain recoverable from image history.
func (e *DockerImageEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	if strings.TrimSpace(e.Image) == "" {
		return fmt.Errorf("docker image is required")
	}
	openFn := e.openFunc
	if openFn == nil {
		openFn = openImage
	}

	img, err := openFn(ctx, e.Image)
	if err != nil {
		return err
	}

	if manifest, err := img.RawManifest(); err == nil {
		if err := e.emitMetadata(ctx, manifest, "manifest.json", callback); err != nil {
			return err
		}
	}
	if config, err := img.RawConfigFile(); err == nil {
		if err := e.emitMetadata(ctx, config, "config.json", callback); err != nil {
			return err
		}
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("listing image layers: %w", err)
	}
	for _, layer := range layers {
		if err := e.scanLayer(ctx, layer, callback); err != nil {
			return err
		}
	}
	return nil
}

func (e *DockerImageEnumerator) scanLayer(ctx context.Context, layer v1.Layer, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	diffID, err := layer.DiffID()
	if err != nil {
		return fmt.Errorf("reading layer diff id: %w", err)
	}
	layerName := diffID.String()

	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("opening layer %s: %w", layerName, err)
	}
	scanErr := e.processLayer(ctx, layerName, rc, callback)
	closeErr := rc.Close()
	if scanErr != nil {
		return scanErr
	}
	if closeErr != nil {
		return fmt.Errorf("closing layer %s: %w", layerName, closeErr)
	}
	return nil
}

// openImage resolves the image source: a path on disk is loaded as a
// docker-save tarball (file) or OCI image layout (directory); anything else
// is parsed as a registry reference and pulled via the OCI distribution API.
// No docker daemon or `docker` binary is required.
func openImage(ctx context.Context, image string) (v1.Image, error) {
	target := strings.TrimSpace(image)
	if info, err := os.Stat(target); err == nil {
		if info.IsDir() {
			return openOCILayout(target)
		}
		return openTarball(target)
	}

	ref, err := name.ParseReference(target)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", target, err)
	}
	img, err := remote.Image(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", target, err)
	}
	return img, nil
}

func openTarball(path string) (v1.Image, error) {
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, fmt.Errorf("opening docker tarball %s: %w", path, err)
	}
	return img, nil
}

func openOCILayout(dir string) (v1.Image, error) {
	p, err := layout.FromPath(dir)
	if err != nil {
		return nil, fmt.Errorf("opening OCI layout %s: %w", dir, err)
	}
	ii, err := p.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("reading OCI image index %s: %w", dir, err)
	}
	m, err := ii.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading OCI manifest %s: %w", dir, err)
	}
	if len(m.Manifests) == 0 {
		return nil, fmt.Errorf("OCI layout %s has no manifests", dir)
	}
	img, err := ii.Image(m.Manifests[0].Digest)
	if err != nil {
		return nil, fmt.Errorf("loading image from OCI layout %s: %w", dir, err)
	}
	return img, nil
}

func (e *DockerImageEnumerator) processLayer(ctx context.Context, layerName string, r io.Reader, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	tr := tar.NewReader(r)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading docker layer %s: %w", layerName, err)
		}
		if !isRegularTarFile(hdr) {
			continue
		}

		memberPath := cleanImagePath(hdr.Name)
		if memberPath == "." || isDockerWhiteout(memberPath) {
			continue
		}

		content, ok, err := readTarFileContent(tr, hdr.Size, e.config.MaxFileSize)
		if err != nil {
			return fmt.Errorf("reading docker layer file %s: %w", memberPath, err)
		}
		if !ok {
			continue
		}

		if err := e.emitLayerFile(ctx, content, layerName, memberPath, callback); err != nil {
			return err
		}
	}
}

func (e *DockerImageEnumerator) emitMetadata(ctx context.Context, content []byte, name string, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if isBinary(content) {
		return nil
	}

	blobID := types.ComputeBlobID(content)
	prov := types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"source": "docker",
			"image":  e.Image,
			"type":   "metadata",
			"path":   dockerArchivePath(e.Image, name),
		},
	}
	return callback(content, blobID, prov)
}

func (e *DockerImageEnumerator) emitLayerFile(ctx context.Context, content []byte, layerName, memberPath string, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	layerArchivePath := dockerArchivePath(e.Image, layerName)

	if isBinary(content) {
		if e.config.ExtractArchives == "" {
			return nil
		}
		ext := getExtension(memberPath)
		if !shouldExtract(e.config, ext) {
			return nil
		}
		extracted, err := ExtractText(memberPath, content, e.config.ExtractLimits)
		if err != nil || len(extracted) == 0 {
			return nil
		}
		nestedArchivePath := layerArchivePath + ":" + memberPath
		for _, ec := range extracted {
			blobID := types.ComputeBlobID(ec.Content)
			prov := types.ArchiveProvenance{
				ArchivePath: nestedArchivePath,
				MemberPath:  ec.Name,
			}
			if err := callback(ec.Content, blobID, prov); err != nil {
				return err
			}
		}
		return nil
	}

	blobID := types.ComputeBlobID(content)
	prov := types.ArchiveProvenance{
		ArchivePath: layerArchivePath,
		MemberPath:  memberPath,
	}
	return callback(content, blobID, prov)
}

func readTarFileContent(r io.Reader, size, maxSize int64) ([]byte, bool, error) {
	if maxSize > 0 && size > maxSize {
		return nil, false, nil
	}
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, false, err
	}
	if maxSize > 0 && int64(len(content)) > maxSize {
		return nil, false, nil
	}
	return content, true, nil
}

func isRegularTarFile(hdr *tar.Header) bool {
	return hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA
}

func isDockerWhiteout(memberPath string) bool {
	for _, part := range strings.Split(memberPath, "/") {
		if strings.HasPrefix(part, ".wh.") {
			return true
		}
	}
	return false
}

func cleanImagePath(name string) string {
	cleaned := path.Clean(strings.TrimPrefix(name, "/"))
	if cleaned == "." {
		return "."
	}
	return strings.TrimPrefix(cleaned, "./")
}

func dockerArchivePath(image, memberPath string) string {
	return "docker://" + strings.TrimPrefix(image, "docker://") + "/" + memberPath
}

// ParseDockerImageReference parses docker://image[:tag] targets.
func ParseDockerImageReference(raw string) (image string, ok bool) {
	if !strings.HasPrefix(raw, "docker://") {
		return "", false
	}
	image = strings.TrimSpace(strings.TrimPrefix(raw, "docker://"))
	if image == "" {
		return "", false
	}
	return image, true
}
