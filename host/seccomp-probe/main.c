// SPDX-License-Identifier: MIT

/*
 * Host probe for the UML seccomp backend.
 *
 * pocket_vm requires UML's seccomp userspace backend (seccomp=on); it never
 * falls back to ptrace. That backend is not a single feature test. It needs a
 * precise set of host behaviours: a filter installed with TSYNC under
 * NO_NEW_PRIVS, SECCOMP_RET_TRAP delivered as SIGSYS with complete metadata,
 * seccomp_data.instruction_pointer populated so the filter can tell stub code
 * from guest code, and -- the part a capability list never covers -- a signal
 * frame whose register edits survive rt_sigreturn, because that write-back is
 * how UML returns a syscall result to its guest.
 *
 * This probe exercises each of those directly, in the same shapes UML uses,
 * and reports what the host actually does rather than what its version number
 * implies. It is deliberately free of pocket_vm dependencies so it can be
 * carried to a candidate host on its own.
 *
 * Every check runs in a forked child: several of them are expected to die by
 * SIGSYS, and a filter cannot be uninstalled once it is on.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/*
 * EL7's UAPI headers predate most of this. Supply every constant the probe
 * needs so it compiles identically against old and current headers, and so a
 * missing declaration can never be mistaken for a missing kernel feature.
 */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER		1
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL	2
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC	(1UL << 0)
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS	0x80000000U
#endif
#ifndef SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_KILL_THREAD		0x00000000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP		0x00030000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW		0x7fff0000U
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS		38
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP			1
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC			0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING		0x0002U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC			0x0010U
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC		(1U << 2)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH			0x1000
#endif

/*
 * Syscall numbers are used numerically on purpose. A host whose headers lack
 * __NR_close_range still has a kernel that may or may not implement 436, and
 * that difference is exactly what the probe is here to measure.
 */
#define NR_X86_64_GETPID		39
#define NR_X86_64_CLOSE			3
#define NR_X86_64_NANOSLEEP		35
#define NR_X86_64_CLOCK_NANOSLEEP	230
#define NR_X86_64_MEMFD_CREATE		319
#define NR_X86_64_GETRANDOM		318
#define NR_X86_64_SECCOMP		317
#define NR_X86_64_EXECVEAT		322
#define NR_X86_64_CLOSE_RANGE		436

#if !defined(__x86_64__)
#error "this probe targets x86-64 hosts"
#endif

#define STUB_PAGE_MASK		0xfffffffffffff000UL

/* An arbitrary value no syscall would return, to prove the edit travelled. */
#define WRITEBACK_SENTINEL	0x5ecc0bad

static int failures;
static int checks;

static void report(int ok, const char *fmt, ...)
{
	va_list args;

	checks += 1;
	if (!ok)
		failures += 1;

	va_start(args, fmt);
	printf("%-5s ", ok ? "ok" : "FAIL");
	vprintf(fmt, args);
	printf("\n");
	va_end(args);
	fflush(stdout);
}

static void note(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printf("      ");
	vprintf(fmt, args);
	printf("\n");
	va_end(args);
	fflush(stdout);
}

/*
 * Raw syscall entry with the call site's address returned alongside the
 * result. seccomp reports the instruction pointer *after* the syscall
 * instruction, so capturing that label is what lets the probe assert the
 * reported si_call_addr and the resumed RIP exactly rather than approximately.
 */
static long raw_syscall6(long nr, long a1, long a2, long a3, long a4, long a5,
			 long a6, void **after)
{
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	long result;
	void *resume;

	__asm__ __volatile__(
		"syscall\n\t"
		"1:\n\t"
		"leaq 1b(%%rip), %1\n\t"
		: "=a"(result), "=r"(resume)
		: "0"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
		: "rcx", "r11", "memory");

	if (after)
		*after = resume;
	return result;
}

static long raw_syscall(long nr, long a1, long a2, long a3)
{
	return raw_syscall6(nr, a1, a2, a3, 0, 0, 0, NULL);
}

static int install_filter(struct sock_filter *filter, unsigned short len,
			  unsigned int flags)
{
	struct sock_fprog prog = {
		.len = len,
		.filter = filter,
	};

	return (int)raw_syscall(NR_X86_64_SECCOMP, SECCOMP_SET_MODE_FILTER,
				(long)flags, (long)&prog);
}

static int no_new_privs(void)
{
	return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

/*
 * A syscall gate placed on a page the probe owns, so that "which page did this
 * syscall come from" has an exact answer. UML's real filter makes precisely
 * this distinction between its stub page and every other address in the
 * process.
 *
 * The gate is written as machine code rather than inline asm so that the
 * syscall instruction is guaranteed to sit on the mapped page and nowhere
 * else. It shuffles the SysV argument registers into the syscall registers:
 * the compiler passes (nr, a1, a2, a3) in rdi/rsi/rdx/rcx, while the syscall
 * instruction wants them in rax/rdi/rsi/rdx.
 */
static const unsigned char gate_code[] = {
	0x48, 0x89, 0xf8,	/* mov %rdi, %rax  -- syscall number   */
	0x48, 0x89, 0xf7,	/* mov %rsi, %rdi  -- first argument   */
	0x48, 0x89, 0xd6,	/* mov %rdx, %rsi  -- second argument  */
	0x48, 0x89, 0xca,	/* mov %rcx, %rdx  -- third argument   */
	0x0f, 0x05,		/* syscall                             */
	0xc3,			/* ret                                 */
};

typedef long (*gate_fn)(long nr, long a1, long a2, long a3);

static void *map_gate(void)
{
	void *page;

	page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return NULL;

	memcpy(page, gate_code, sizeof(gate_code));
	if (mprotect(page, 4096, PROT_READ | PROT_EXEC) != 0) {
		munmap(page, 4096);
		return NULL;
	}

	return page;
}

static long call_gate(void *page, long nr, long a1, long a2, long a3)
{
	gate_fn gate = (gate_fn)page;

	return gate(nr, a1, a2, a3);
}

/*
 * SIGSYS siginfo as the kernel lays it out on x86-64. glibc 2.17 has no
 * _sigsys member, so the probe overlays the ABI directly rather than
 * depending on the header's vintage.
 */
struct sigsys_siginfo {
	int si_signo;
	int si_errno;
	int si_code;
	int pad;
	void *call_addr;
	int syscall_nr;
	unsigned int arch;
};

static int child_status(pid_t pid, int *signal_out, int *exit_out)
{
	int status;

	*signal_out = 0;
	*exit_out = -1;

	if (waitpid(pid, &status, 0) != pid)
		return -1;
	if (WIFSIGNALED(status))
		*signal_out = WTERMSIG(status);
	else if (WIFEXITED(status))
		*exit_out = WEXITSTATUS(status);
	return 0;
}

static pid_t spawn(void (*body)(void *), void *argument)
{
	pid_t pid = fork();

	if (pid == 0) {
		body(argument);
		_exit(120);
	}
	return pid;
}

/* ---------------------------------------------------------------- probes -- */

struct syscall_presence {
	const char *name;
	long nr;
	long a1, a2, a3;
	long observed;
};

static void probe_presence(void *argument)
{
	struct syscall_presence *entry = argument;

	entry->observed = raw_syscall(entry->nr, entry->a1, entry->a2, entry->a3);
	_exit(0);
}

static long syscall_presence(long nr, long a1, long a2, long a3)
{
	/*
	 * Shared anonymous memory rather than a pipe: the call under test may
	 * be close_range, which would take the pipe with it.
	 */
	struct syscall_presence *shared;
	long observed;
	pid_t pid;
	int signal_number, exit_code;

	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED)
		return -ENOMEM;

	shared->nr = nr;
	shared->a1 = a1;
	shared->a2 = a2;
	shared->a3 = a3;
	/* Not a plausible return from any syscall probed here, so a result
	 * left untouched cannot be mistaken for one that was measured. */
	shared->observed = -ECHILD;

	pid = spawn(probe_presence, shared);
	if (pid < 0) {
		munmap(shared, sizeof(*shared));
		return -ECHILD;
	}
	/*
	 * A child that died on a signal, or exited any way but cleanly, never
	 * stored a result: the shared page still holds the initial value. That
	 * is not an observation, and reporting it as one would call a syscall
	 * "present" on the strength of a crash, so it is refused by name.
	 */
	if (child_status(pid, &signal_number, &exit_code) != 0 ||
	    signal_number != 0 || exit_code != 0)
		shared->observed = -ECHILD;

	observed = shared->observed;
	munmap(shared, sizeof(*shared));
	return observed;
}

static const char *presence_word(long observed)
{
	if (observed == -ECHILD)
		return "unmeasured";
	return observed == -ENOSYS ? "absent" : "present";
}

static int action_query_unsupported(long observed)
{
	return observed == -EINVAL || observed == -EOPNOTSUPP;
}

/* -- SIGSYS metadata and register write-back ------------------------------- */

struct sigsys_observation {
	int delivered;
	int si_code;
	int syscall_nr;
	unsigned int arch;
	void *call_addr;
	unsigned long saved_rax;
	unsigned long saved_rdi;
	unsigned long saved_rsi;
	unsigned long saved_rip;
	unsigned long resumed_rax;
	void *expected_after;
};

static struct sigsys_observation *observation;

static void sigsys_writeback_handler(int sig, siginfo_t *info, void *context)
{
	struct sigsys_siginfo *raw = (struct sigsys_siginfo *)info;
	ucontext_t *uc = context;

	(void)sig;

	observation->delivered = 1;
	observation->si_code = raw->si_code;
	observation->syscall_nr = raw->syscall_nr;
	observation->arch = raw->arch;
	observation->call_addr = raw->call_addr;
	observation->saved_rax = (unsigned long)uc->uc_mcontext.gregs[REG_RAX];
	observation->saved_rdi = (unsigned long)uc->uc_mcontext.gregs[REG_RDI];
	observation->saved_rsi = (unsigned long)uc->uc_mcontext.gregs[REG_RSI];
	observation->saved_rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];

	/*
	 * The write-back UML depends on: edit the saved return register and
	 * let rt_sigreturn carry it back to the interrupted code.
	 */
	uc->uc_mcontext.gregs[REG_RAX] = (greg_t)WRITEBACK_SENTINEL;
}

static void probe_sigsys_writeback(void *argument)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X86_64_CLOCK_NANOSLEEP, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
	};
	const struct timespec zero = { .tv_sec = 0, .tv_nsec = 0 };
	struct sigaction sa;
	void *after = NULL;
	long result;

	(void)argument;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_ONSTACK | SA_NODEFER | SA_SIGINFO;
	sa.sa_sigaction = sigsys_writeback_handler;
	if (sigaction(SIGSYS, &sa, NULL) < 0)
		_exit(2);

	if (no_new_privs() != 0)
		_exit(3);
	if (install_filter(filter, 4, SECCOMP_FILTER_FLAG_TSYNC) != 0)
		_exit(4);

	result = raw_syscall6(NR_X86_64_CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 0,
			      (long)&zero, 0, 0, 0, &after);

	observation->resumed_rax = (unsigned long)result;
	observation->expected_after = after;
	_exit(0);
}

/* -- instruction_pointer discrimination ------------------------------------ */

struct gate_observation {
	int trapped_from_gate;
	int allowed_off_gate;
	void *call_addr;
	int syscall_nr;
	unsigned long gate_page;
};

static struct gate_observation *gate_observation;

static void gate_trap_handler(int sig, siginfo_t *info, void *context)
{
	struct sigsys_siginfo *raw = (struct sigsys_siginfo *)info;
	ucontext_t *uc = context;

	(void)sig;

	gate_observation->trapped_from_gate = 1;
	gate_observation->call_addr = raw->call_addr;
	gate_observation->syscall_nr = raw->syscall_nr;

	/* Return a benign value so the gate call can simply unwind. */
	uc->uc_mcontext.gregs[REG_RAX] = (greg_t)0;
}

static void probe_gate_trap(void *argument)
{
	void *page = argument;
	unsigned long target = (unsigned long)page & STUB_PAGE_MASK;
	struct sock_filter filter[] = {
		/* Trap only syscalls issued from the gate page. */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, instruction_pointer) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)(target >> 32), 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, instruction_pointer)),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xfffff000),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)(target & 0xfffff000), 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
	};
	struct sigaction sa;

	gate_observation->gate_page = target;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_ONSTACK | SA_NODEFER | SA_SIGINFO;
	sa.sa_sigaction = gate_trap_handler;
	if (sigaction(SIGSYS, &sa, NULL) < 0)
		_exit(2);

	if (no_new_privs() != 0)
		_exit(3);
	if (install_filter(filter, 7, SECCOMP_FILTER_FLAG_TSYNC) != 0)
		_exit(4);

	/* Off the gate page: must be allowed and must really run. */
	if (raw_syscall(NR_X86_64_GETPID, 0, 0, 0) > 0)
		gate_observation->allowed_off_gate = 1;

	/* On the gate page: must trap. */
	call_gate(page, NR_X86_64_GETPID, 0, 0, 0);

	_exit(0);
}

/* -- the kill action UML's filter actually returns ------------------------- */

static void probe_kill_action(void *argument)
{
	void *page = argument;
	unsigned long target = (unsigned long)page & STUB_PAGE_MASK;
	struct sock_filter filter[] = {
		/* Allow syscalls from the gate page, kill everything else. */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, instruction_pointer) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)(target >> 32), 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, instruction_pointer)),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xfffff000),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)(target & 0xfffff000), 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	if (no_new_privs() != 0)
		_exit(3);
	if (install_filter(filter, 7, SECCOMP_FILTER_FLAG_TSYNC) != 0)
		_exit(4);

	/* Permitted: from the gate page. EBADF proves it really executed. */
	if (call_gate(page, NR_X86_64_CLOSE, -1, 0, 0) != -EBADF)
		_exit(5);

	/* Not permitted: must not survive this. */
	raw_syscall(NR_X86_64_GETPID, 0, 0, 0);
	_exit(6);
}

/* -- glibc sleep(0) issues no syscall at all ------------------------------- */

struct sleep_observation {
	int slept_without_syscall;
	int raw_call_trapped;
};

static struct sleep_observation *sleep_observation;

static void sleep_trap_handler(int sig, siginfo_t *info, void *context)
{
	ucontext_t *uc = context;

	(void)sig;
	(void)info;

	sleep_observation->raw_call_trapped = 1;
	uc->uc_mcontext.gregs[REG_RAX] = (greg_t)0;
}

static void probe_sleep_zero(void *argument)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X86_64_CLOCK_NANOSLEEP, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NR_X86_64_NANOSLEEP, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
	};
	const struct timespec zero = { .tv_sec = 0, .tv_nsec = 0 };
	struct sigaction sa;

	(void)argument;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_ONSTACK | SA_NODEFER | SA_SIGINFO;
	sa.sa_sigaction = sleep_trap_handler;
	if (sigaction(SIGSYS, &sa, NULL) < 0)
		_exit(2);

	if (no_new_privs() != 0)
		_exit(3);
	if (install_filter(filter, 5, SECCOMP_FILTER_FLAG_TSYNC) != 0)
		_exit(4);

	/*
	 * This is the call the upstream UML probe makes. If the host's libc
	 * short-circuits it, the filtered syscall never happens and the probe
	 * reaches its failure sentinel while the kernel was in fact capable.
	 */
	sleep(0);
	if (!sleep_observation->raw_call_trapped)
		sleep_observation->slept_without_syscall = 1;

	/* The same intent, expressed as the syscall the filter names. */
	raw_syscall6(NR_X86_64_CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 0,
		     (long)&zero, 0, 0, 0, NULL);

	_exit(0);
}

/* ------------------------------------------------------------------ main -- */

static void describe_host(void)
{
	struct utsname host;

	if (uname(&host) == 0)
		note("host %s %s %s", host.sysname, host.release, host.machine);
#ifdef __GLIBC__
	note("built against glibc %d.%d", __GLIBC__, __GLIBC_MINOR__);
#endif
}

int main(void)
{
	struct sigsys_observation *sigsys_shared;
	struct gate_observation *gate_shared;
	struct sleep_observation *sleep_shared;
	long close_range_result, execveat_result, memfd_result, memfd_exec_result;
	long getrandom_result, action_avail;
	void *gate_page;
	pid_t pid;
	int signal_number, exit_code;

	printf("pocket host seccomp probe\n");
	describe_host();

	gate_page = map_gate();
	if (gate_page == NULL) {
		printf("FAIL  cannot map an executable page for the probe gate\n");
		printf("POCKET_HOST_SECCOMP_PROBE_FAILED\n");
		return 1;
	}
	report(1, "mapped an executable probe page (PROT_EXEC available)");

	/* --- syscall presence ------------------------------------------- */

	close_range_result = syscall_presence(NR_X86_64_CLOSE_RANGE, 1, ~0U, 0);
	note("close_range(436): %s (raw %ld)",
	     presence_word(close_range_result), close_range_result);

	execveat_result = syscall_presence(NR_X86_64_EXECVEAT, -1, 0, 0);
	note("execveat(322): %s (raw %ld)",
	     presence_word(execveat_result), execveat_result);

	memfd_result = syscall_presence(NR_X86_64_MEMFD_CREATE,
					(long)"pocket-probe",
					MFD_CLOEXEC | MFD_ALLOW_SEALING, 0);
	report(memfd_result >= 0, "memfd_create(319) is available (raw %ld)",
	       memfd_result);

	memfd_exec_result = syscall_presence(NR_X86_64_MEMFD_CREATE,
					     (long)"pocket-probe",
					     MFD_CLOEXEC | MFD_EXEC, 0);
	note("memfd_create with MFD_EXEC: %s (raw %ld)",
	     memfd_exec_result >= 0 ? "accepted" : "rejected", memfd_exec_result);

	getrandom_result = syscall_presence(NR_X86_64_GETRANDOM, 0, 0, 0);
	report(getrandom_result >= 0 || getrandom_result == -EFAULT,
	       "getrandom(318) is available (raw %ld)", getrandom_result);

	action_avail = syscall_presence(NR_X86_64_SECCOMP,
					SECCOMP_GET_ACTION_AVAIL, 0,
					(long)&(unsigned int){ SECCOMP_RET_KILL_PROCESS });
	/*
	 * A kernel that predates the query rejects it, but not uniformly:
	 * 3.10 answers EOPNOTSUPP where later kernels answer EINVAL. Anything
	 * that decides "can I ask for KILL_PROCESS?" must accept both, or it
	 * will misread exactly the hosts it was written for.
	 */
	note("SECCOMP_GET_ACTION_AVAIL(KILL_PROCESS): raw %ld%s",
	     action_avail, action_query_unsupported(action_avail) ?
			   " (query unsupported on this kernel)" : "");

	/* --- SIGSYS metadata and register write-back --------------------- */

	sigsys_shared = mmap(NULL, sizeof(*sigsys_shared),
			     PROT_READ | PROT_WRITE,
			     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sigsys_shared == MAP_FAILED) {
		printf("FAIL  cannot map shared observation memory\n");
		printf("POCKET_HOST_SECCOMP_PROBE_FAILED\n");
		return 1;
	}
	memset(sigsys_shared, 0, sizeof(*sigsys_shared));
	observation = sigsys_shared;

	pid = spawn(probe_sigsys_writeback, NULL);
	if (pid < 0 || child_status(pid, &signal_number, &exit_code) != 0) {
		report(0, "seccomp filter probe child could not be run");
	} else {
		report(exit_code == 0,
		       "NO_NEW_PRIVS + SECCOMP_SET_MODE_FILTER with TSYNC accepted"
		       " (child exit %d, signal %d)", exit_code, signal_number);
		report(sigsys_shared->delivered,
		       "SECCOMP_RET_TRAP delivered SIGSYS to the handler");
		report(sigsys_shared->si_code == SYS_SECCOMP,
		       "si_code is SYS_SECCOMP (observed %d)",
		       sigsys_shared->si_code);
		report(sigsys_shared->syscall_nr == NR_X86_64_CLOCK_NANOSLEEP,
		       "si_syscall names the filtered call (observed %d)",
		       sigsys_shared->syscall_nr);
		report(sigsys_shared->arch == AUDIT_ARCH_X86_64,
		       "si_arch is AUDIT_ARCH_X86_64 (observed 0x%x)",
		       sigsys_shared->arch);
		report(sigsys_shared->saved_rax == NR_X86_64_CLOCK_NANOSLEEP,
		       "ucontext RAX holds the original syscall number (observed %lu)",
		       sigsys_shared->saved_rax);
		report(sigsys_shared->saved_rdi == CLOCK_MONOTONIC,
		       "ucontext RDI holds the first syscall argument (observed %lu)",
		       sigsys_shared->saved_rdi);
		/*
		 * These two compare one recorded field against another, so
		 * without the delivery guard they would both read 0 == 0 and
		 * pass on a host where the handler never ran -- reporting the
		 * resume address as correct on the strength of never having
		 * measured it.
		 */
		report(sigsys_shared->delivered &&
			       sigsys_shared->expected_after != NULL &&
			       sigsys_shared->saved_rip ==
				       (unsigned long)sigsys_shared->expected_after,
		       "ucontext RIP resumes after the syscall instruction");
		report(sigsys_shared->delivered &&
			       sigsys_shared->expected_after != NULL &&
			       sigsys_shared->call_addr ==
				       sigsys_shared->expected_after,
		       "si_call_addr matches the instruction after the syscall");
		report(sigsys_shared->resumed_rax == WRITEBACK_SENTINEL,
		       "register edits in the signal frame survive rt_sigreturn"
		       " (observed 0x%lx)", sigsys_shared->resumed_rax);
	}
	munmap(sigsys_shared, sizeof(*sigsys_shared));

	/* --- instruction_pointer discrimination -------------------------- */

	gate_shared = mmap(NULL, sizeof(*gate_shared), PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (gate_shared == MAP_FAILED) {
		printf("FAIL  cannot map shared gate observation memory\n");
		printf("POCKET_HOST_SECCOMP_PROBE_FAILED\n");
		return 1;
	}
	memset(gate_shared, 0, sizeof(*gate_shared));
	gate_observation = gate_shared;

	pid = spawn(probe_gate_trap, gate_page);
	if (pid < 0 || child_status(pid, &signal_number, &exit_code) != 0) {
		report(0, "instruction-pointer probe child could not be run");
	} else {
		report(gate_shared->allowed_off_gate,
		       "a syscall outside the watched page was allowed");
		report(gate_shared->trapped_from_gate,
		       "a syscall from the watched page trapped");
		report(((unsigned long)gate_shared->call_addr & STUB_PAGE_MASK) ==
			       gate_shared->gate_page,
		       "seccomp_data.instruction_pointer identified the exact page");
		report(gate_shared->syscall_nr == NR_X86_64_GETPID,
		       "the trapped call was the expected one (observed %d)",
		       gate_shared->syscall_nr);
	}
	munmap(gate_shared, sizeof(*gate_shared));

	/* --- the kill action UML's filter returns ------------------------ */

	pid = spawn(probe_kill_action, gate_page);
	if (pid < 0 || child_status(pid, &signal_number, &exit_code) != 0) {
		report(0, "kill-action probe child could not be run");
	} else {
		report(signal_number == SIGSYS,
		       "an unpermitted syscall killed the task via SIGSYS"
		       " (signal %d, exit %d)", signal_number, exit_code);
		note("UML returns SECCOMP_RET_KILL_PROCESS (0x%08x); this kernel %s",
		     SECCOMP_RET_KILL_PROCESS,
		     action_query_unsupported(action_avail) ?
			     "predates that action and applies its legacy kill" :
			     "advertises the action query");
	}

	/* --- the libc short-circuit the upstream probe walks into -------- */

	sleep_shared = mmap(NULL, sizeof(*sleep_shared), PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sleep_shared == MAP_FAILED) {
		printf("FAIL  cannot map shared sleep observation memory\n");
		printf("POCKET_HOST_SECCOMP_PROBE_FAILED\n");
		return 1;
	}
	memset(sleep_shared, 0, sizeof(*sleep_shared));
	sleep_observation = sleep_shared;

	pid = spawn(probe_sleep_zero, NULL);
	if (pid < 0 || child_status(pid, &signal_number, &exit_code) != 0) {
		report(0, "sleep(0) probe child could not be run");
	} else {
		report(sleep_shared->raw_call_trapped,
		       "a raw clock_nanosleep reaches the filter");
		note("this libc's sleep(0) %s the filtered syscall",
		     sleep_shared->slept_without_syscall ? "never issues" : "issues");
	}
	munmap(sleep_shared, sizeof(*sleep_shared));

	/* --- verdict ------------------------------------------------------ */

	printf("\n%d checks, %d failed\n", checks, failures);
	if (close_range_result == -ENOSYS || execveat_result == -ENOSYS) {
		printf("host lacks %s%s%s; UML needs pocket's EL7 compatibility"
		       " patches on this host\n",
		       close_range_result == -ENOSYS ? "close_range" : "",
		       (close_range_result == -ENOSYS &&
			execveat_result == -ENOSYS) ? " and " : "",
		       execveat_result == -ENOSYS ? "execveat" : "");
	}
	if (failures != 0) {
		printf("POCKET_HOST_SECCOMP_PROBE_FAILED\n");
		return 1;
	}
	printf("POCKET_HOST_SECCOMP_PROBE_OK\n");
	return 0;
}
