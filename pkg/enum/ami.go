package enum

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/praetorian-inc/titus/pkg/enum/ignore"
	"github.com/praetorian-inc/titus/pkg/types"
)

// AMITarget is a remote EBS-backed AMI or a local raw disk image.
type AMITarget struct {
	// ImageID is set for a remote AMI (ami-xxxxxxxx).
	ImageID string
	// Region overrides the AWS SDK default. ami://region/ami-id wins over --region.
	Region string
	// Path is set for a local raw disk image (dd, coldsnap download, qemu-img -O raw).
	Path string
}

// AMIEnumerator scans files inside an Amazon Machine Image or a raw disk image.
//
// Remote scans use ec2:DescribeImages plus the EBS direct APIs
// (ebs:ListSnapshotBlocks, ebs:GetSnapshotBlock). The snapshot must be owned by
// or shared with the caller; marketplace and merely-public snapshots are not
// readable. Instance-store AMIs, LVM, and filesystems other than ext2/3/4 and
// XFS are not scanned.
type AMIEnumerator struct {
	Target AMITarget
	config Config

	// open overrides disk resolution. Tests set it; production leaves it nil.
	open func(ctx context.Context, e *AMIEnumerator) ([]amiVolume, error)
	// clients overrides the AWS SDK clients. Tests set it.
	clients func(ctx context.Context, region string) (*amiClients, error)
}

type amiClients struct {
	images    amiImageAPI
	snapshots snapshotBlockAPI
	region    string
}

type amiImageAPI interface {
	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

// NewAMIEnumerator creates an enumerator for an AMI ID or a local raw disk image.
// region is the --region override and is ignored when target.Region or target.Path is set.
func NewAMIEnumerator(target AMITarget, region string, config Config) *AMIEnumerator {
	if target.Region == "" && target.Path == "" {
		target.Region = strings.TrimSpace(region)
	}
	return &AMIEnumerator{Target: target, config: config}
}

// ParseAMIReference parses ami://ami-id and ami://region/ami-id.
func ParseAMIReference(raw string) (AMITarget, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "ami://") {
		return AMITarget{}, false
	}
	rest := strings.Trim(raw[len("ami://"):], "/")
	if rest == "" {
		return AMITarget{}, false
	}
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 1:
		id, ok := normalizeAMIID(parts[0])
		if !ok {
			return AMITarget{}, false
		}
		return AMITarget{ImageID: id}, true
	case 2:
		region := strings.ToLower(parts[0])
		id, ok := normalizeAMIID(parts[1])
		if !ok || !validRegion(region) {
			return AMITarget{}, false
		}
		return AMITarget{ImageID: id, Region: region}, true
	default:
		return AMITarget{}, false
	}
}

// AMITargetFromFlag parses a --ami argument: an ami:// URL, a bare AMI ID, or a local path.
func AMITargetFromFlag(raw string) (AMITarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AMITarget{}, fmt.Errorf("AMI target is required")
	}
	if parsed, ok := ParseAMIReference(raw); ok {
		return parsed, nil
	}
	if id, ok := normalizeAMIID(raw); ok {
		return AMITarget{ImageID: id}, nil
	}
	return AMITarget{Path: raw}, nil
}

// Enumerate yields regular files from every EBS snapshot on the AMI, or from a local raw disk.
func (e *AMIEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	ig, err := ignore.CompilePatterns(e.config.IgnoreFile)
	if err != nil {
		return err
	}
	var volumes []amiVolume
	if e.open != nil {
		volumes, err = e.open(ctx, e)
	} else {
		volumes, err = e.openVolumes(ctx)
	}
	if err != nil {
		return err
	}
	defer closeVolumes(volumes)
	if len(volumes) == 0 {
		return fmt.Errorf("no disks to scan")
	}

	var opened int
	var notes []string
	for _, vol := range volumes {
		fmt.Fprintf(os.Stderr, "[ami] scanning %s (%s)\n", vol.Label, formatByteSize(vol.Size))
		n, skipped, err := scanAMIDisk(ctx, vol, e.config, ig, callback)
		if err != nil {
			return fmt.Errorf("%s: %w", vol.Label, err)
		}
		opened += n
		notes = append(notes, skipped...)
	}
	for _, note := range notes {
		fmt.Fprintf(os.Stderr, "[ami] %s\n", note)
	}
	if opened == 0 {
		return fmt.Errorf("no supported filesystem found (ext2/3/4 or xfs on GPT, MBR, or a raw disk; LVM is not supported)")
	}
	return nil
}

func (e *AMIEnumerator) openVolumes(ctx context.Context) ([]amiVolume, error) {
	if e.Target.Path != "" {
		return openLocalAMIDisk(e.Target.Path)
	}
	if e.Target.ImageID == "" {
		return nil, fmt.Errorf("AMI ID is required")
	}
	return e.openRemoteAMI(ctx)
}

func openLocalAMIDisk(path string) ([]amiVolume, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening disk image: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat disk image: %w", err)
	}
	if info.IsDir() {
		f.Close()
		return nil, fmt.Errorf("AMI disk image %s is a directory; pass a raw disk image", path)
	}
	if info.Size() == 0 {
		f.Close()
		return nil, fmt.Errorf("AMI disk image %s is empty", path)
	}
	return []amiVolume{{
		Label: localAMILabel(path),
		Disk:  f,
		Size:  info.Size(),
		close: func() { f.Close() },
	}}, nil
}

func (e *AMIEnumerator) openRemoteAMI(ctx context.Context) ([]amiVolume, error) {
	load := e.clients
	if load == nil {
		load = defaultAMIClients
	}
	clients, err := load(ctx, e.Target.Region)
	if err != nil {
		return nil, err
	}
	out, err := clients.images.DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{e.Target.ImageID},
	})
	if err != nil {
		return nil, fmt.Errorf("describing AMI %s: %w", e.Target.ImageID, err)
	}
	if out == nil || len(out.Images) == 0 {
		return nil, fmt.Errorf("AMI %s not found", e.Target.ImageID)
	}
	img := out.Images[0]
	if img.State != "" && img.State != ec2types.ImageStateAvailable {
		return nil, fmt.Errorf("AMI %s is %s, not available", e.Target.ImageID, img.State)
	}
	specs, err := ebsVolumeSpecs(img, e.Target.ImageID)
	if err != nil {
		return nil, err
	}
	region := e.Target.Region
	if region == "" {
		region = clients.region
	}
	volumes := make([]amiVolume, 0, len(specs))
	for _, spec := range specs {
		reader, err := newSnapshotReader(ctx, clients.snapshots, spec.SnapshotID)
		if err != nil {
			return nil, wrapSnapshotReadError(spec.SnapshotID, err)
		}
		volumes = append(volumes, amiVolume{
			Label:      remoteAMILabel(region, e.Target.ImageID, spec.Device),
			Disk:       reader,
			Size:       reader.Size(),
			SnapshotID: spec.SnapshotID,
			Device:     spec.Device,
		})
	}
	return volumes, nil
}

func defaultAMIClients(ctx context.Context, region string) (*amiClients, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("AWS region is required to scan an AMI (set --region, use ami://region/ami-id, or configure AWS_REGION)")
	}
	return &amiClients{
		images:    ec2.NewFromConfig(cfg),
		snapshots: ebs.NewFromConfig(cfg),
		region:    cfg.Region,
	}, nil
}

type amiVolumeSpec struct {
	Device     string
	SnapshotID string
}

// ebsVolumeSpecs returns the EBS snapshots attached to an AMI, root device first.
func ebsVolumeSpecs(img ec2types.Image, imageID string) ([]amiVolumeSpec, error) {
	root := aws.ToString(img.RootDeviceName)
	var rootSpecs, rest []amiVolumeSpec
	seen := make(map[string]struct{})
	for _, mapping := range img.BlockDeviceMappings {
		if mapping.Ebs == nil || mapping.Ebs.SnapshotId == nil || *mapping.Ebs.SnapshotId == "" {
			continue
		}
		id := *mapping.Ebs.SnapshotId
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		device := aws.ToString(mapping.DeviceName)
		if device == "" {
			device = id
		}
		spec := amiVolumeSpec{Device: device, SnapshotID: id}
		if root != "" && device == root {
			rootSpecs = append(rootSpecs, spec)
			continue
		}
		rest = append(rest, spec)
	}
	specs := append(rootSpecs, rest...)
	if len(specs) == 0 {
		if img.RootDeviceType == ec2types.DeviceTypeInstanceStore {
			return nil, fmt.Errorf("AMI %s is instance-store backed; only EBS-backed AMIs can be scanned", imageID)
		}
		return nil, fmt.Errorf("AMI %s has no EBS snapshots to scan", imageID)
	}
	return specs, nil
}

func wrapSnapshotReadError(snapshotID string, err error) error {
	var apiErr smithy.APIError
	if asSmithyAPIError(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException", "UnauthorizedOperation", "AccessDenied":
			return fmt.Errorf("reading snapshot %s: %w (EBS direct APIs only read snapshots you own or that were shared with you; marketplace and public AMI snapshots are unsupported — copy the AMI into this account and scan the copy)", snapshotID, err)
		}
	}
	return fmt.Errorf("reading snapshot %s: %w", snapshotID, err)
}

func remoteAMILabel(region, imageID, device string) string {
	if region == "" {
		region = "aws"
	}
	device = strings.TrimPrefix(device, "/")
	return fmt.Sprintf("ami://%s/%s/%s", region, imageID, device)
}

func localAMILabel(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return "ami://" + filepath.ToSlash(abs)
}

func normalizeAMIID(raw string) (string, bool) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if !strings.HasPrefix(id, "ami-") {
		return "", false
	}
	hexPart := id[len("ami-"):]
	if len(hexPart) != 8 && len(hexPart) != 17 {
		return "", false
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return id, true
}

func validRegion(region string) bool {
	if len(region) < 7 || len(region) > 32 || !strings.Contains(region, "-") {
		return false
	}
	for _, c := range region {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func formatByteSize(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// gitIgnore is the subset of the ignore matcher AMI walks use.
type gitIgnore interface {
	MatchesPath(string) bool
}
