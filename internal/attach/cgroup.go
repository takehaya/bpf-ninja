package attach

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// cgroupSKBAttachTypes are the cgroup attach points a
// BPF_PROG_TYPE_CGROUP_SKB program can hang off — the set the --cgroup
// selector enumerates.
var cgroupSKBAttachTypes = []ebpf.AttachType{
	ebpf.AttachCGroupInetIngress,
	ebpf.AttachCGroupInetEgress,
}

// FindCgroupSKBPrograms enumerates the cgroup-skb programs attached
// (directly, not inherited) to the given cgroup v2 path via
// BPF_PROG_QUERY, and opens each as a probe target. Peer of
// FindXDPProgram for the cgroup world: `--cgroup /sys/fs/cgroup/foo`
// is to cgroup-skb what `-i eth0` is to XDP.
func FindCgroupSKBPrograms(cgroupPath string) ([]*ProgInfo, error) {
	dir, err := os.Open(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("opening cgroup %s: %w", cgroupPath, err)
	}
	defer func() { _ = dir.Close() }()

	seen := map[ebpf.ProgramID]bool{}
	var ids []ebpf.ProgramID
	for _, at := range cgroupSKBAttachTypes {
		res, err := link.QueryPrograms(link.QueryOptions{Target: int(dir.Fd()), Attach: at})
		if err != nil {
			return nil, fmt.Errorf("querying %s programs on %s: %w", at, cgroupPath, err)
		}
		for _, p := range res.Programs {
			if !seen[p.ID] {
				seen[p.ID] = true
				ids = append(ids, p.ID)
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no cgroup-skb programs attached to %s (BPF_PROG_QUERY over ingress+egress found none)", cgroupPath)
	}

	var infos []*ProgInfo
	for _, id := range ids {
		info, err := FindBPFProgramByID(uint32(id))
		if err != nil {
			for _, prev := range infos {
				_ = prev.Program.Close()
			}
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}
