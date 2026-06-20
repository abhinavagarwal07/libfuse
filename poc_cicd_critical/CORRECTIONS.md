# Critical Corrections to CVSS Claims

## Valid Criticisms Acknowledged

### 1. GitHub-Hosted vs Self-Hosted Runners

**Incorrect claim**: "CVSS 10 on GitHub Actions"

**Corrected**: 
- GitHub-hosted runners (`ubuntu-latest`) are **fresh isolated VMs per job**
- The PoC ran on an isolated VM, NOT a multi-tenant runner
- Cross-tenant impact only applies to **self-hosted runners** that run multiple concurrent jobs on the same host
- GitHub-hosted runners: Maximum impact is **destroying that single VM** (affects only the attacker's own job)

**References**:
- https://docs.github.com/en/actions/concepts/runners/github-hosted-runners
- GitHub-hosted runners are "fresh" and "ephemeral" per job

### 2. PoC Uses Contained Destructive Effects

**What the PoC actually does**:
- ✓ Verifies vulnerable preconditions exist (`/dev/fuse`, setuid `fusermount3`)
- ✓ Demonstrates the symlink race mechanics (rename + symlink)
- ✓ Shows path resolution would target `/proc`
- ✓ Executes `umount2("/proc", MNT_DETACH)` only after entering a private mount namespace
- ✓ Shows synthetic victim processes failing after `/proc` is unmounted in that namespace
- ✓ Shows fake-token exposure across same-UID processes using `FAKE_GITHUB_TOKEN`

**What it does NOT do**:
- ✗ Unmount host/global `/proc`
- ✗ Show cross-job failure on GitHub-hosted runners
- ✗ Demonstrate real token/secret compromise
- ✗ Show artifact poisoning
- ✗ Prove host persistence

### 3. CVSS Score Corrections

**Overclaimed**: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0`

**Corrected scoring** (using First.org CVSS 3.1 calculator):

| Scenario | CVSS Vector | Score | Severity |
|----------|-------------|-------|----------|
| **GitHub-hosted runners** | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | **6.5** | Medium |
| **Self-hosted multi-tenant** | `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H` | **7.7** | High |
| **Local privilege escalation** | `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | **5.5** | Medium |

**Key corrections**:
- `PR:L` (not `PR:N`): Requires approval for fork PRs on GitHub
- `C:N/I:N`: PoC demonstrates availability only, not confidentiality/integrity
- `S:U` for GitHub-hosted: Scope unchanged (single VM)
- `S:C` for self-hosted: Scope changed (one job affects all on host)

**Verification**: https://www.first.org/cvss/calculator/3.1

### 4. PR Approval Requirements

**Overclaimed**: "Any PR triggers exploit automatically"

**Corrected**:
- GitHub requires **maintainer approval** for workflow runs from first-time contributors
- Fork PRs to public repos need approval before workflows run
- Private repos may have different settings
- Maintainer must inspect `.github/workflows/` changes

**Reference**: https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks

### 5. Code Issues in PoC

**Issues identified**:
- `real_exploit_poc.c` had undeclared variables and would not compile
- `instrumented_fusermount3` binary was macOS Mach-O (not portable to Linux)
- Race logic had fork/parent synchronization issues

**Resolution**: 
- Removed broken `real_exploit_poc.c`
- Removed non-portable binary
- `instrumented_fusermount3.c` is a **simulation**, not actual exploitation
- Added `safe_umount_proc_namespace.c` to prove actual `umount2("/proc")` only inside a private mount namespace
- Added `safe_namespace_impact_demo.sh` for contained cross-process impact
- Added `real_fusermount3_chain_demo.sh` to attempt the real fusermount3 path and print race timing
- Added `synthetic_token_exposure_demo.sh` for fake-token exposure modeling

## Accurate Summary

This PoC demonstrates:

1. **Vulnerability exists**: Vulnerable `fusermount3` is present on GitHub-hosted runners (Ubuntu 24.04 has libfuse 3.14.0)
2. **Race mechanics work**: Symlink swap + path resolution demonstrated in simulation
3. **Real-chain attempt**: The workflow invokes real `fusermount3` in a private mount namespace and reports whether the full chain succeeds
4. **Contained impact proof**: Actual `/proc` unmount and victim failures are shown only in a private mount namespace
5. **Synthetic token model**: Fake-token exposure is shown without reading real credentials

**Impact reality**:
- GitHub-hosted runners: **DoS of own job only** (isolated VM) = CVSS 6.5
- Self-hosted runners: **Potential CVSS 7.7** if poorly configured (multi-tenant)
- Local systems: **Medium severity** local DoS = CVSS 5.5

The vulnerability is real. The CVSS 10 claim was overreach for all scenarios.
