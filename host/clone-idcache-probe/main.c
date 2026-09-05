/*
 * Does a CLONE_VM clone corrupt the caller's libc id cache?
 *
 * glibc before 2.25 caches the pid and tid in the thread control block. Its
 * clone() wrapper stores -1 into both for a CLONE_VM clone that is not
 * CLONE_THREAD, on the assumption that the child gets its own TCB. UML clones
 * without CLONE_SETTLS, so the child shares the caller's TCB and the write
 * lands in the *parent*. From then on the parent's cached ids are -1, and
 * anything that addresses a thread by id fails: pthread_cancel() cannot signal
 * the thread it is cancelling, so a subsequent join never returns.
 *
 * Three arms, each in its own process so a corrupted cache cannot leak into
 * the next one:
 *
 *   baseline   cancel and join a helper thread, having cloned nothing
 *   raw        the same, after a clone issued as a bare syscall
 *   libc       the same, after a clone issued through libc's wrapper
 *
 * "joins" means the helper was cancelled and joined within the timeout.
 * "hangs" means it was not: the join did not return, which is the defect.
 *
 * This is the experiment behind patch 0009. It reports what it observes on
 * whatever host runs it and never decides which answer is correct, so the same
 * binary is evidence on a host that has the defect and on one that does not.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHILD_STACK_BYTES (256 * 1024)
#define JOIN_TIMEOUT_SECONDS 5

enum arm { ARM_BASELINE, ARM_RAW_CLONE, ARM_LIBC_CLONE };

static void *idle_thread(void *unused)
{
	(void)unused;
	for (;;)
		pause();
	return NULL;
}

static int clone_child(void *unused)
{
	(void)unused;
	_exit(0);
}

/*
 * clone(2) as a bare syscall, with the child entered directly rather than
 * returned into C. This is what patch 0009 does in the kernel's stub, reduced
 * to the part that matters here: no libc wrapper runs, so nothing writes to
 * the caller's TCB.
 */
static long raw_clone_vm(void *stack_top)
{
	register long r10 __asm__("r10") = 0;
	register long r8 __asm__("r8") = 0;
	unsigned long *child_stack;
	long ret;

	child_stack = (unsigned long *)((unsigned long)stack_top & ~15UL);

	__asm__ volatile (
		"syscall\n\t"
		"testq %%rax, %%rax\n\t"
		"jnz 1f\n\t"
		"xorq %%rbp, %%rbp\n\t"
		"movl $0, %%edi\n\t"
		"movl %[exit], %%eax\n\t"
		"syscall\n\t"
		"hlt\n\t"
		"1:\n\t"
		: "=a" (ret)
		: "0" ((long)SYS_clone),
		  "D" ((long)(CLONE_VM | CLONE_VFORK | SIGCHLD)),
		  "S" (child_stack), "d" (0L), "r" (r10), "r" (r8),
		  [exit] "i" (SYS_exit)
		: "rcx", "r11", "memory");
	return ret;
}

static int run_clone(enum arm which)
{
	void *stack;
	long rc;

	if (which == ARM_BASELINE)
		return 0;

	stack = mmap(NULL, CHILD_STACK_BYTES, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack == MAP_FAILED)
		return -1;

	if (which == ARM_RAW_CLONE)
		rc = raw_clone_vm((char *)stack + CHILD_STACK_BYTES);
	else
		rc = clone(clone_child, (char *)stack + CHILD_STACK_BYTES,
			   CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);

	if (rc > 0)
		while (waitpid((pid_t)rc, NULL, 0) < 0 && errno == EINTR)
			;
	munmap(stack, CHILD_STACK_BYTES);
	return rc < 0 ? -1 : 0;
}

/* 0 joined, 1 timed out, 2 could not run the arm at all. */
static int arm_body(enum arm which)
{
	struct timespec deadline;
	pthread_t helper;

	if (pthread_create(&helper, NULL, idle_thread, NULL) != 0)
		return 2;
	/* Let the helper reach pause() before it is cancelled. */
	usleep(100000);

	if (run_clone(which) != 0)
		return 2;

	pthread_cancel(helper);
	if (clock_gettime(CLOCK_REALTIME, &deadline) != 0)
		return 2;
	deadline.tv_sec += JOIN_TIMEOUT_SECONDS;
	return pthread_timedjoin_np(helper, NULL, &deadline) == 0 ? 0 : 1;
}

static const char *run_arm(enum arm which)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return "unmeasured";
	if (pid == 0)
		_exit(arm_body(which));
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	if (!WIFEXITED(status))
		return "unmeasured";
	switch (WEXITSTATUS(status)) {
	case 0:
		return "joins";
	case 1:
		return "hangs";
	default:
		return "unmeasured";
	}
}

int main(void)
{
	const char *baseline, *raw, *libc_arm;

	printf("pocket clone/id-cache probe\n");
#ifdef __GLIBC__
	printf("      built against glibc %d.%d\n", __GLIBC__, __GLIBC_MINOR__);
#else
	printf("      built against a libc that is not glibc\n");
#endif

	baseline = run_arm(ARM_BASELINE);
	raw = run_arm(ARM_RAW_CLONE);
	libc_arm = run_arm(ARM_LIBC_CLONE);

	printf("      baseline (no clone):    %s\n", baseline);
	printf("      after a raw clone:      %s\n", raw);
	printf("      after a libc clone:     %s\n", libc_arm);

	if (strcmp(baseline, "joins") != 0 || strcmp(raw, "joins") != 0) {
		printf("FAIL  a raw CLONE_VM clone must leave the caller able to "
		       "join a cancelled thread\n");
		printf("POCKET_CLONE_IDCACHE_PROBE_FAILED\n");
		return 1;
	}
	if (strcmp(libc_arm, "joins") == 0)
		printf("ok    this libc's clone() leaves the id cache alone\n");
	else
		printf("ok    this libc's clone() corrupts the caller's id cache; "
		       "the raw clone is what avoids it\n");
	printf("POCKET_CLONE_IDCACHE_PROBE_OK\n");
	return 0;
}
