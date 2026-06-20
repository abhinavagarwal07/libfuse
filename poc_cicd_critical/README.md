# fusermount3 Symlink Race - Security Research

**DISCLAIMER**: This repository is for authorized security research. Destructive effects are contained in a private mount namespace, and token exposure is demonstrated only with synthetic data.

## Overview

This demonstrates a vulnerability in `libfuse` `fusermount3` that exists on CI/CD runners and other Linux systems.

## What This Actually Demonstrates

- Vulnerable `fusermount3` is present on GitHub-hosted runners
- Symlink race mechanics (rename + symlink swap)
- Path resolution changes that would target `/proc`
- Optional end-to-end probe that invokes real `/usr/bin/fusermount3`, passes an unconnected `_FUSE_COMMFD`, measures the mountinfo-to-swap timing, and checks whether `/proc` is detached
- Actual `umount2("/proc", MNT_DETACH)` in a private mount namespace only
- Cross-process "victim job" failures after `/proc` is unmounted in that namespace
- A real GitHub-hosted attacker/victim job pair showing whether cross-job impact occurs on `ubuntu-latest`
- Fallback real unmount of a throwaway tmpfs mountpoint when namespace `/proc` proof is unavailable
- Synthetic same-UID token exposure using a fake `FAKE_GITHUB_TOKEN`

## What This Does NOT Demonstrate

- Host/global unmount of `/proc`
- Cross-job failure on GitHub-hosted runners
- Real `GITHUB_TOKEN` or repository secret compromise
- Artifact poisoning
- Supply chain attacks

## CVSS Scoring (Corrected)

| Scenario | Vector | Score |
|----------|--------|-------|
| GitHub-hosted runners | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | **6.5 (Medium)** |
| Self-hosted multi-tenant | `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H` | **7.7 (High)** |
| Local | `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | **5.5 (Medium)** |

**Note**: GitHub-hosted runners use isolated VMs per job - no cross-tenant impact.

## Vulnerability Summary

- **Component**: libfuse `fusermount3`
- **Location**: `util/fusermount.c:1820`
- **Type**: Missing `UMOUNT_NOFOLLOW` in cleanup path
- **Impact**: Arbitrary unmount as root if the race is won; this repository demonstrates the destructive syscall only inside a private mount namespace

## Repository Contents

```
poc_cicd_critical/
├── poc_cicd_uaf.sh            # Setup script
├── instrumented_fusermount3.c # Simulation code
├── safe_umount_proc_namespace.c
├── safe_namespace_impact_demo.sh
├── safe_tmpfs_unmount_demo.sh
├── real_fusermount3_chain_probe.c
├── real_fusermount3_chain_demo.sh
├── synthetic_token_exposure_demo.sh
├── .github/workflows/
│   └── real_exploit.yml       # Demonstration workflow
├── CORRECTIONS.md             # Acknowledged issues
└── README.md                  # This file
```

## Technical Summary

The vulnerability is a symlink race in the error cleanup path of `fusermount3`. When `send_fd()` fails, the cleanup code calls `umount2(mnt, MNT_DETACH)` without:
1. Dropping privileges
2. Using `UMOUNT_NOFOLLOW`
3. Pinning the mountpoint

`instrumented_fusermount3.c` demonstrates the race mechanics but does not execute the actual exploit. `real_fusermount3_chain_demo.sh` attempts the end-to-end chain against the real `/usr/bin/fusermount3` inside a private mount namespace and prints timing data for the mountinfo event and symlink swap. `safe_namespace_impact_demo.sh` separately proves that `umount2("/proc", MNT_DETACH)` breaks concurrent processes, but only after `safe_umount_proc_namespace.c` verifies it is running in a private mount namespace. If that proof cannot run, `safe_tmpfs_unmount_demo.sh` performs a real unmount of a throwaway tmpfs mountpoint. The root GitHub workflow also runs separate attacker and victim jobs on `ubuntu-latest` and compares their reports; this is the real GitHub-hosted evidence for whether cross-job impact occurs. `synthetic_token_exposure_demo.sh` models a self-hosted runner isolation failure with a fake token; it does not read real secrets.

## References

- [libfuse/libfuse](https://github.com/libfuse/libfuse)
- [First.org CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [GitHub Runner Documentation](https://docs.github.com/en/actions/concepts/runners)

## License

For security research purposes only.
