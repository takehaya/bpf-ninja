package output

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Tag-split output naming. With --split-by-tag, each per-CPU shard writes a
// live file per tag it sees, and a clean shutdown merges them per tag:
//
//	live shard file : <stem>.cpu<shard>.<tag><ext>   (e.g. out.cpu0.1.pcap)
//	merged per tag  : <stem>.<tag><ext>              (e.g. out.1.pcap)
//
// The tag is the set-map value of the matched entry (0 when no set matched),
// inserted before the extension so `out.pcap` becomes `out.1.pcap`.

// splitStem splits a -w base path into its stem and extension so a tag can
// be inserted before the extension. An empty extension (no dot) just gets
// the tag appended.
func splitStem(base string) (stem, ext string) {
	ext = filepath.Ext(base)
	return strings.TrimSuffix(base, ext), ext
}

// TagShardPath is the live per-(shard, tag) file a split capture writes to.
func TagShardPath(base string, shard int, tag uint32) string {
	stem, ext := splitStem(base)
	return fmt.Sprintf("%s.cpu%d.%d%s", stem, shard, tag, ext)
}

// TagMergedPath is the per-tag file a split capture merges its shards into.
func TagMergedPath(base string, tag uint32) string {
	stem, ext := splitStem(base)
	return fmt.Sprintf("%s.%d%s", stem, tag, ext)
}

// MergeTagShards discovers every <stem>.cpu<N>.<tag><ext> shard file left by
// a split capture and merges the shards of each tag into <stem>.<tag><ext>.
// Discovery reads the output directory and matches names with a regex, so a
// -w path containing glob metacharacters (`[`, `?`, ...) is handled
// correctly. It works whether the capture shut down cleanly (in-process) or
// was killed and is being reconciled later by the `merge` subcommand. The
// shard files are left in place.
func MergeTagShards(basePath string, cfg Config) error {
	ext := filepath.Ext(basePath)
	dir := filepath.Dir(basePath)
	baseStem := strings.TrimSuffix(filepath.Base(basePath), ext)
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(baseStem) + `\.cpu\d+\.(\d+)` + regexp.QuoteMeta(ext) + `$`)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading output directory %s: %w", dir, err)
	}
	tagFiles := map[uint32][]string{}
	for _, e := range entries {
		sm := re.FindStringSubmatch(e.Name())
		if sm == nil {
			continue
		}
		tag, err := strconv.ParseUint(sm[1], 10, 32)
		if err != nil {
			continue
		}
		tagFiles[uint32(tag)] = append(tagFiles[uint32(tag)], filepath.Join(dir, e.Name()))
	}

	tags := make([]uint32, 0, len(tagFiles))
	for tag := range tagFiles {
		tags = append(tags, tag)
	}
	slices.Sort(tags)

	for _, tag := range tags {
		files := tagFiles[tag]
		slices.Sort(files) // deterministic input order across shards
		if err := mergeFiles(files, TagMergedPath(basePath, tag), cfg); err != nil {
			return fmt.Errorf("merging tag %d: %w", tag, err)
		}
	}
	return nil
}
