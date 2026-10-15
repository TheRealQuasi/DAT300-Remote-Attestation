/*
 * bench.h - attestation benchmark for the CA (fTPM or TPM).
 *
 * Bench mode is ON only when the environment variable BENCH_OUT is set.
 * Without it (normal mode) every bench_* call does nothing.
 *
 * Measured per attestation request, from just before the first TPM
 * command to just after the response to the last one:
 *   t_ftpm_ns   : wall-clock time (CLOCK_MONOTONIC)              -> T_att
 *   busy/total  : /proc/stat ticks, all cores summed             -> U
 *                 U = busy / total = 1 - (idle + iowait) / total
 *   cpu_proc_ns : CPU time charged to the CA process (not used in report)
 *   rss_kb      : peak memory of the CA so far       (not used in report)
 *
 *   bench_start(&b);     // just before the first TPM command
 *   ... TPM call(s) ...
 *   bench_stop(&b);      // just after the last response
 *   bench_log(&b);       // appends one CSV row to $BENCH_OUT
 *   if (bench_done(&b))  // true after $BENCH_REQUESTS requests (if set)
 *           exit(0);
 */

#ifndef BENCH_H
#define BENCH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct bench {
	unsigned seq;
	uint64_t t0, t1;
	uint64_t cpu0, cpu1;
	unsigned long long busy0, total0, busy1, total1;
};

// Checked before calling start, stop, log and done as 
// normal mode and bench mode share the same binary
static inline int bench_on(void)
{
	return getenv("BENCH_OUT") != NULL;
}

/*
 * USED IN REPORT (CPU load U, columns busy_ticks and total_ticks).
 * Reads the first line of /proc/stat: CPU ticks (10 ms each) since boot,
 * summed over all cores. Called at start and stop; the differences give
 *   U = busy / total = 1 - (idle + iowait) / total
 * System-wide, so it includes all work on the attester during the request
 * (CA, kernel, tee-supplicant, secure world), not only the CA process.
 */
static inline void bench_cpu(unsigned long long *busy, unsigned long long *total)
{
	unsigned long long v[8] = { 0 };
	FILE *f = fopen("/proc/stat", "r");

	if (f) {
		if (fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
			   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) < 4)
			v[0] = v[1] = v[2] = v[3] = 0;
		fclose(f);
	}
	/* user nice system idle iowait irq softirq steal */
	*total = v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
	*busy = *total - v[3] - v[4];
}

/*
 * NOT USED IN REPORT. Extra data only (column cpu_proc_ns).
 * CPU time charged to the CA process itself (user + kernel), in ns.
 * Misses work done by other processes for the request (e.g. tee-supplicant),
 * so it underestimates the load.
 */
static inline uint64_t bench_cpu_proc(void)
{
	struct timespec t;

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

/*
 * NOT USED IN REPORT. Extra data only (column rss_kb).
 * Peak RAM used by the CA process so far (VmHWM), in kB.
 */
static inline unsigned long bench_rss_kb(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	unsigned long kb = 0;
	char line[128];

	if (f) {
		while (fgets(line, sizeof(line), f))
			if (sscanf(line, "VmHWM: %lu kB", &kb) == 1)
				break;
		fclose(f);
	}
	return kb;
}

/*
 * USED IN REPORT (latency T_att, column t_ftpm_ns).
 * Current time in nanoseconds from CLOCK_MONOTONIC. This clock only moves
 * forward and is not affected if the system time is changed (NTP, date),
 * so it is the right clock for measuring durations. Read at start and
 * stop; the difference is the wall-clock time of the request.
 */
static inline uint64_t bench_now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

static inline void bench_start(struct bench *b)
{
	if (!bench_on())
		return;
	bench_cpu(&b->busy0, &b->total0);
	b->cpu0 = bench_cpu_proc();
	b->t0 = bench_now();
}

static inline void bench_stop(struct bench *b)
{
	if (!bench_on())
		return;
	b->t1 = bench_now();
	b->cpu1 = bench_cpu_proc();
	bench_cpu(&b->busy1, &b->total1);
}

static inline void bench_log(struct bench *b)
{
	FILE *f;

	if (!bench_on() || !(f = fopen(getenv("BENCH_OUT"), "a")))
		return;
	if (ftell(f) == 0)
		fprintf(f, "seq,t_ftpm_ns,cpu_proc_ns,busy_ticks,total_ticks,rss_kb\n");
	fprintf(f, "%u,%llu,%llu,%llu,%llu,%lu\n", b->seq++,
		(unsigned long long)(b->t1 - b->t0),
		(unsigned long long)(b->cpu1 - b->cpu0),
		b->busy1 - b->busy0, b->total1 - b->total0,
		bench_rss_kb());
	fclose(f);
}

/* true once $BENCH_REQUESTS requests have been logged */
static inline int bench_done(struct bench *b)
{
	const char *n = getenv("BENCH_REQUESTS");

	return bench_on() && n && b->seq >= (unsigned)atoi(n);
}

#endif /* BENCH_H */