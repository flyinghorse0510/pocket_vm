// SPDX-License-Identifier: MIT

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define WORKERS 4
#define ITERATIONS_PER_WORKER UINT64_C(400000000)

static void power_off(int status)
{
	fflush(NULL);
	sync();
	if (reboot(RB_POWER_OFF) == -1)
		fprintf(stderr, "POCKET_SMP_ERROR reboot errno=%d\n", errno);
	_exit(status);
}

static void fail(const char *operation)
{
	fprintf(stderr, "POCKET_SMP_ERROR %s errno=%d\n", operation, errno);
	power_off(1);
}

static uint64_t burn(unsigned int worker)
{
	volatile uint64_t state = UINT64_C(0x9e3779b97f4a7c15) ^ worker;
	uint64_t index;

	for (index = 0; index < ITERATIONS_PER_WORKER; ++index)
		state = (state * UINT64_C(2862933555777941757)) +
			UINT64_C(3037000493) + (index >> 7);
	return state;
}

static uint64_t elapsed_ns(const struct timespec *start,
			   const struct timespec *end)
{
	uint64_t seconds = (uint64_t)(end->tv_sec - start->tv_sec);
	int64_t nanoseconds = end->tv_nsec - start->tv_nsec;

	if (nanoseconds < 0) {
		--seconds;
		nanoseconds += 1000000000L;
	}
	return seconds * UINT64_C(1000000000) + (uint64_t)nanoseconds;
}

int main(void)
{
	int start_pipe[2];
	int result_pipe[2];
	pid_t children[WORKERS];
	struct timespec start;
	struct timespec end;
	uint64_t checksum = 0;
	long online;
	unsigned int worker;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	if (pipe(start_pipe) == -1 || pipe(result_pipe) == -1)
		fail("pipe");

	for (worker = 0; worker < WORKERS; ++worker) {
		pid_t child = fork();
		if (child == -1)
			fail("fork");
		if (child == 0) {
			char token;
			uint64_t result;
			ssize_t count;

			close(start_pipe[1]);
			close(result_pipe[0]);
			do {
				count = read(start_pipe[0], &token, sizeof(token));
			} while (count == -1 && errno == EINTR);
			if (count != (ssize_t)sizeof(token))
				_exit(20);
			result = burn(worker);
			do {
				count = write(result_pipe[1], &result, sizeof(result));
			} while (count == -1 && errno == EINTR);
			_exit(count == (ssize_t)sizeof(result) ? 0 : 21);
		}
		children[worker] = child;
	}

	close(start_pipe[0]);
	close(result_pipe[1]);
	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		fail("clock_gettime-start");
	for (worker = 0; worker < WORKERS; ++worker) {
		char token = (char)worker;
		if (write(start_pipe[1], &token, sizeof(token)) != (ssize_t)sizeof(token))
			fail("barrier-write");
	}
	close(start_pipe[1]);

	for (worker = 0; worker < WORKERS; ++worker) {
		uint64_t result;
		ssize_t count;

		do {
			count = read(result_pipe[0], &result, sizeof(result));
		} while (count == -1 && errno == EINTR);
		if (count != (ssize_t)sizeof(result))
			fail("result-read");
		checksum ^= result;
	}
	close(result_pipe[0]);
	for (worker = 0; worker < WORKERS; ++worker) {
		int status;
		if (waitpid(children[worker], &status, 0) != children[worker])
			fail("waitpid");
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			errno = ECHILD;
			fail("worker-status");
		}
	}
	if (clock_gettime(CLOCK_MONOTONIC, &end) == -1)
		fail("clock_gettime-end");
	online = sysconf(_SC_NPROCESSORS_ONLN);
	if (online < 1)
		fail("sysconf-online-cpus");

	printf("POCKET_SMP_OK workers=%u online=%ld iterations=%" PRIu64
	       " elapsed_ns=%" PRIu64 " checksum=%016" PRIx64 "\n",
	       WORKERS, online, ITERATIONS_PER_WORKER,
	       elapsed_ns(&start, &end), checksum);
	power_off(0);
}
