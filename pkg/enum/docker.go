package enum

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"

	"github.com/praetorian-inc/titus/pkg/types"
)

// DockerImageEnumerator enumerates scan blobs from a Docker image archive.
type DockerImageEnumerator struct {
	Image string

	config   Config
	saveFunc func(ctx context.Context, image string) (io.ReadCloser, error)
}

// NewDockerImageEnumerator creates an enumerator for a local Docker image.
func NewDockerImageEnumerator(image string, config Config) *DockerImageEnumerator {
	if parsed, ok := ParseDockerImageReference(image); ok {
		image = parsed
	}
	return &DockerImageEnumerator{
		Image:    image,
		config:   config,
		saveFunc: dockerImageSave,
	}
}

// Enumerate streams `docker image save` output and scans image metadata plus
// every regular file found in each filesystem layer. Lower-layer files are
// intentionally included even when later layers delete them, because secrets
// can remain recoverable from image history.
func (e *DockerImageEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	if strings.TrimSpace(e.Image) == "" {
		return fmt.Errorf("docker image is required")
	}
	if e.saveFunc == nil {
		e.saveFunc = dockerImageSave
	}

	rc, err := e.saveFunc(ctx, e.Image)
	if err != nil {
		return err
	}

	enumErr := e.enumerateImageArchive(ctx, rc, callback)
	closeErr := rc.Close()
	if enumErr != nil {
		return enumErr
	}
	return closeErr
}

func dockerImageSave(ctx context.Context, image string) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, "docker", "image", "save", image)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("preparing docker image save: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting docker image save: %w", err)
	}

	return &dockerSaveReadCloser{
		image:  image,
		stdout: stdout,
		cmd:    cmd,
		stderr: stderr,
	}, nil
}

type dockerSaveReadCloser struct {
	image  string
	stdout io.ReadCloser
	cmd    *exec.Cmd
	stderr *bytes.Buffer
}

func (c *dockerSaveReadCloser) Read(p []byte) (int, error) {
	return c.stdout.Read(p)
}

func (c *dockerSaveReadCloser) Close() error {
	_ = c.stdout.Close()
	if err := c.cmd.Wait(); err != nil {
		msg := strings.TrimSpace(c.stderr.String())
		if msg != "" {
			return fmt.Errorf("docker image save %q: %w: %s", c.image, err, msg)
		}
		return fmt.Errorf("docker image save %q: %w", c.image, err)
	}
	return nil
}

func (e *DockerImageEnumerator) enumerateImageArchive(ctx context.Context, r io.Reader, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
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
			return fmt.Errorf("reading docker image archive: %w", err)
		}
		if !isRegularTarFile(hdr) {
			continue
		}

		name := cleanImagePath(hdr.Name)
		switch {
		case isDockerLayerTar(name):
			if err := e.processLayer(ctx, name, tr, callback); err != nil {
				return err
			}
		case isDockerLayerTarGZ(name):
			gz, err := gzip.NewReader(tr)
			if err != nil {
				return fmt.Errorf("opening compressed docker layer %s: %w", name, err)
			}
			if err := e.processLayer(ctx, name, gz, callback); err != nil {
				_ = gz.Close()
				return err
			}
			if err := gz.Close(); err != nil {
				return fmt.Errorf("closing compressed docker layer %s: %w", name, err)
			}
		case isDockerBlob(name):
			if err := e.processBlob(ctx, name, tr, hdr.Size, callback); err != nil {
				return err
			}
		case strings.HasSuffix(strings.ToLower(name), ".json") || name == "repositories":
			content, ok, err := readTarFileContent(tr, hdr.Size, e.config.MaxFileSize)
			if err != nil {
				return fmt.Errorf("reading docker metadata %s: %w", name, err)
			}
			if ok {
				if err := e.emitMetadata(ctx, content, name, callback); err != nil {
					return err
				}
			}
		}
	}
}

func (e *DockerImageEnumerator) processBlob(ctx context.Context, name string, r io.Reader, size int64, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	br := bufio.NewReader(r)
	if isGzipReader(br) {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("opening docker blob layer %s: %w", name, err)
		}
		if err := e.processLayer(ctx, name, gz, callback); err != nil {
			_ = gz.Close()
			return err
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("closing docker blob layer %s: %w", name, err)
		}
		return nil
	}

	if isJSONReader(br) {
		content, ok, err := readTarFileContent(br, size, e.config.MaxFileSize)
		if err != nil {
			return fmt.Errorf("reading docker blob metadata %s: %w", name, err)
		}
		if !ok {
			return nil
		}
		return e.emitMetadata(ctx, content, name, callback)
	}

	return e.processLayer(ctx, name, br, callback)
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

func isDockerLayerTar(name string) bool {
	lower := strings.ToLower(name)
	return lower == "layer.tar" || strings.HasSuffix(lower, "/layer.tar")
}

func isDockerLayerTarGZ(name string) bool {
	lower := strings.ToLower(name)
	return lower == "layer.tar.gz" || strings.HasSuffix(lower, "/layer.tar.gz") ||
		lower == "layer.tgz" || strings.HasSuffix(lower, "/layer.tgz")
}

func isDockerBlob(name string) bool {
	return strings.HasPrefix(name, "blobs/sha256/") && len(strings.TrimPrefix(name, "blobs/sha256/")) == 64
}

func isGzipReader(r *bufio.Reader) bool {
	header, err := r.Peek(2)
	return err == nil && header[0] == 0x1f && header[1] == 0x8b
}

func isJSONReader(r *bufio.Reader) bool {
	header, err := r.Peek(512)
	if err != nil && len(header) == 0 {
		return false
	}
	trimmed := bytes.TrimSpace(header)
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
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
