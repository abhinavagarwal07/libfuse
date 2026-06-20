/*
 * Safe umount2("/proc") proof helper.
 *
 * This intentionally performs the destructive syscall only after guard checks
 * prove the process is in a private mount namespace. It is meant to be launched
 * by safe_namespace_impact_demo.sh, not run directly on a host.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MNT_DETACH
#define MNT_DETACH 0x00000002
#endif

static int read_ns_link(const char *path, char *buf, size_t size)
{
	ssize_t len;

	len = readlink(path, buf, size - 1);
	if (len < 0)
		return -1;

	buf[len] = '\0';
	return 0;
}

static void die_guard(const char *msg)
{
	fprintf(stderr, "[guard] refusing to call umount2(\"/proc\"): %s\n", msg);
	exit(2);
}

int main(void)
{
	const char *allow = getenv("POC_ALLOW_PROC_UMOUNT");
	const char *parent_ns = getenv("POC_PARENT_MNT_NS");
	char self_ns[128];
	char init_ns[128];
	struct stat st;

	if (allow == NULL || strcmp(allow, "mount-namespace-only") != 0)
		die_guard("missing POC_ALLOW_PROC_UMOUNT=mount-namespace-only");

	if (parent_ns == NULL || parent_ns[0] == '\0')
		die_guard("missing parent mount namespace fingerprint");

	if (read_ns_link("/proc/self/ns/mnt", self_ns, sizeof(self_ns)) != 0)
		die_guard("cannot read current mount namespace");

	if (strcmp(self_ns, parent_ns) == 0)
		die_guard("current mount namespace matches parent");

	if (read_ns_link("/proc/1/ns/mnt", init_ns, sizeof(init_ns)) == 0 &&
	    strcmp(self_ns, init_ns) == 0)
		die_guard("current mount namespace matches pid 1");

	if (stat("/proc/self/status", &st) != 0)
		die_guard("/proc is not mounted before the proof");

	printf("[guard] parent mount namespace: %s\n", parent_ns);
	printf("[guard] child mount namespace:  %s\n", self_ns);
	printf("[proof] calling umount2(\"/proc\", MNT_DETACH) inside private mount namespace\n");

	if (umount2("/proc", MNT_DETACH) != 0) {
		fprintf(stderr, "[proof] umount2 failed: %s\n", strerror(errno));
		return 1;
	}

	printf("[proof] umount2(\"/proc\", MNT_DETACH) returned 0\n");

	if (stat("/proc/self/status", &st) != 0)
		printf("[proof] /proc/self/status is inaccessible after unmount: %s\n",
		       strerror(errno));
	else {
		fprintf(stderr, "[proof] /proc/self/status is still accessible after unmount\n");
		return 1;
	}

	return 0;
}
