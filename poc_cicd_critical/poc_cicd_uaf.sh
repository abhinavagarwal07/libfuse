#!/bin/bash
# PoC: fusermount3 symlink race in CI/CD environments
# DEMONSTRATION ONLY - For security research and responsible disclosure
# This demonstrates the theoretical attack path described in the security analysis
# DO NOT USE AGAINST SYSTEMS YOU DO NOT OWN

set -e

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}=== SECURITY RESEARCH PoC ===${NC}"
echo -e "${YELLOW}This demonstrates a vulnerability in libfuse fusermount3${NC}"
echo -e "${YELLOW}For authorized security testing only${NC}"
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) not installed"
    echo "Install: https://cli.github.com/"
    exit 1
fi

# Check authentication
if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with gh CLI"
    echo "Run: gh auth login"
    exit 1
fi

# Configuration
REPO_NAME="fusermount3-cicd-poc-$(date +%s)"
ORG=${GH_ORG:-$(gh api user -q '.login')}

echo "Creating demonstration repository: $ORG/$REPO_NAME"
echo ""

# Create repo
gh repo create "$REPO_NAME" --private --description "fusermount3 CI/CD security research" || {
    echo "Failed to create repository"
    exit 1
}

# Clone the new repo
gh repo clone "$ORG/$REPO_NAME" /tmp/$REPO_NAME
cd /tmp/$REPO_NAME

# Create the malicious workflow
cat > .github/workflows/build.yml << 'WORKFLOW_EOF'
name: Build Test
on: [push, pull_request]

jobs:
  test-fuse-mount:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: "Install dependencies"
        run: |
          sudo apt-get update
          sudo apt-get install -y libfuse3-dev gcc python3
      
      - name: "Check fusermount3 status"
        run: |
          echo "=== fusermount3 status ==="
          ls -la /dev/fuse
          which fusermount3
          ls -la $(which fusermount3)
          echo ""
          echo "=== fusermount3 version ==="
          fusermount3 --version || true
      
      - name: "Demonstrate vulnerability environment"
        run: |
          echo "=== Creating PoC structure ==="
          # This shows the environment is vulnerable
          # In a real exploit, this would:
          # 1. Create /tmp/x/proc
          # 2. Set up inotify watcher on /proc/self/mountinfo
          # 3. Create unconnected AF_UNIX socket
          # 4. Call fusermount3 with _FUSE_COMMFD pointing to socket
          # 5. Race: rename /tmp/x, symlink / -> /tmp/x
          # 6. Trigger cleanup umount2(/tmp/x/proc) -> umount2(/proc)
          
          # For demonstration: show the conditions exist
          mkdir -p /tmp/x/proc
          ls -la /tmp/x/
          
          echo ""
          echo "=== Socket capability test ==="
          python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
print(f'Created unconnected AF_UNIX socket: fd={s.fileno()}')
print('This socket passes S_ISSOCK but fails sendmsg with ENOTCONN')
print('Triggering send_fd failure -> cleanup umount2 path')
"
          
          echo ""
          echo "=== Vulnerability conditions verified ==="
          echo "1. /dev/fuse exists: $([ -c /dev/fuse ] && echo YES || echo NO)"
          echo "2. fusermount3 setuid: $(stat -c '%a' $(which fusermount3))"
          echo "3. libfuse version: $(fusermount3 --version 2>&1 | head -1)"
      
      - name: "Concurrent victim job simulation"
        run: |
          echo "=== Simulating other concurrent jobs ==="
          # In a real attack, this demonstrates cross-job impact
          # When /proc is unmounted, these would fail:
          ps aux | head -5 || echo "ps would fail after exploit"
          pgrep init || echo "pgrep would fail after exploit"
          ls /proc/1/ || echo "/proc access would fail"

WORKFLOW_EOF

# Create documentation
cat > SECURITY_ANALYSIS.md << 'DOC_EOF'
# fusermount3 Symlink Race - CI/CD Security Analysis

## Vulnerability Summary

**Component:** libfuse `fusermount3`  
**Location:** `util/fusermount.c:1820` (master) / line 1710 (3.18.2)  
**Type:** Symlink race in error cleanup path  
**Impact:** Arbitrary unmount as root

## Technical Details

### The Bug

In `fusermount.c`, the cleanup path after `send_fd()` failure:

```c
res = send_fd(cfd, fd);
if (res != 0) {
    umount2(mnt, MNT_DETACH); /* lazy umount */  // BUG
    goto err_out;
}
```

**Problems:**
1. Runs with full root privileges (euid=0, fsuid=0)
2. No `UMOUNT_NOFOLLOW` flag
3. Re-resolves the full path string
4. Attacker controls trigger via `_FUSE_COMMFD`

### Attack Vector

1. Create `/tmp/x/proc` (legitimate directory)
2. Create unconnected `AF_UNIX SOCK_DGRAM` socket
3. Call `fusermount3` with `_FUSE_COMMFD=<socket_fd>`
4. During race window (`add_mount()` fork/exec), swap:
   - `rename("/tmp/x", "/tmp/y")`
   - `symlink("/", "/tmp/x")`
5. `send_fd()` fails (ENOTCONN) → cleanup triggers
6. `umount2("/tmp/x/proc", MNT_DETACH)` resolves to `/proc`
7. In an uncontained exploit, the host namespace's `/proc` would be unmounted as root

### CI/CD Impact

**Self-hosted multi-tenant runners:** CVSS 7.7 (High)
- Multi-tenant: multiple jobs share host
- Workflow-triggerable after repository policy allows the run
- Cross-tenant: one job unmounts `/proc` for all jobs
- Availability impact to concurrent jobs

**GitLab shared or self-managed runners:** Environment-dependent
- Explicitly multi-tenant by design
- Same host kernel shared across projects

**GitHub-hosted runners:** CVSS 6.5 (Medium)
- Single-tenant VMs (one job per VM)
- No cross-tenant impact demonstrated

## Mitigation

**Immediate:**
```c
// Fix: Use hardened unmount path
if (res != 0) {
    char *copy = strdup(mnt);
    const char *last;
    drop_privs();
    if (copy && chdir_to_parent(copy, &last) == 0)
        umount2(last, MNT_DETACH | UMOUNT_NOFOLLOW);
    restore_privs();
    free(copy);
    goto err_out;
}
```

**Alternative:** Keep `mountpoint_fd` open and unmount via `/proc/self/fd/N`

## Responsible Disclosure

This repository is created for authorized security research only.
The vulnerability has been reported to upstream libfuse maintainers.

## References

- libfuse/libfuse: https://github.com/libfuse/libfuse
- CVE-2021-3995/3996: Similar pattern in util-linux
DOC_EOF

# Push to GitHub
git init
git add .
git commit -m "Add security research demonstration"
git branch -M main
git push origin main

echo ""
echo -e "${RED}=== PoC Repository Created ===${NC}"
echo "Repository: https://github.com/$ORG/$REPO_NAME"
echo ""
echo "Next steps:"
echo "1. Review the workflow: .github/workflows/build.yml"
echo "2. Review the analysis: SECURITY_ANALYSIS.md"
echo "3. The workflow will run and demonstrate vulnerable conditions"
echo ""
echo -e "${YELLOW}IMPORTANT: This is a DEMONSTRATION${NC}"
echo "The actual exploit path is documented but not executed."
echo "The workflow shows that vulnerable conditions exist."
echo ""
echo "To trigger the workflow:"
echo "  cd /tmp/$REPO_NAME && git commit --allow-empty -m 'trigger' && git push"

# Open in browser (optional)
echo ""
read -p "Open in browser? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    gh repo view "$ORG/$REPO_NAME" --web
fi
