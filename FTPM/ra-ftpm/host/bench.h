/*
 * bench.h - fTPM benchmark for the CA.
 *
 * Bench mode is ON only when the environment variable BENCH_OUT is set.
 * Without it (normal mode) every bench_* call does nothing.
 *
 * Measures for each attestation request, over the fTPM call(s) only:
 *   T_FTPM   : wall-clock time, first fTPM command to last response (ns)
 *   CPU_proc : CPU time the CA process itself burned over that interval
 *              (ns, user+system) - isolated from other processes and
 *              independent of how many cores exist. Does NOT include the
 *              secure-world TA; use T_TA for the full end-to-end cost.
 *   U        : system-wide CPU load from /proc/stat over the same interval,
 *              all cores: U = busy / total = 1 - (idle + iowait) / total
 *   RSS      : peak resident set size of the CA so far (VmHWM, kB)
 *
 *   bench_start(&b);     // just before the first fTPM command
 *   ... fTPM call(s) ...
 *   bench_stop(&b);      // just after the last response
 *   bench_log(&b);       // appends one CSV row to $BENCH_OUT
 *   if (bench_done(&b))  // true after $BENCH_REQUESTS requests (if set)
 *           exit(0);
 *
 * NOTE for overhead studies: run QEMU with a fixed core count (e.g.
 * QEMU_SMP=1) so U is not diluted across idle cores, and treat the
 * numbers as RELATIVE (emulated), not absolute hardware figures.
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

static inline int bench_on(void)
{
	return getenv("BENCH_OUT") != NULL;
}

/* first line of /proc/stat = all cores summed */
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

/* CPU time burned by THIS process (user+system), in nanoseconds */
static inline uint64_t bench_cpu_proc(void)
{
	struct timespec t;

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

/* peak resident set size so far (VmHWM from /proc/self/status), in kB */
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