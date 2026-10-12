/*
 * bench.h - fTPM benchmark for the CA.
 *
 * Bench mode is ON only when the environment variable BENCH_OUT is set.
 * Without it (normal mode) every bench_* call does nothing.
 *
 * Measures for each attestation request, over the fTPM call(s) only:
 *   T_TA : time from first fTPM command to response of the last (ns)
 *   U    : CPU load from /proc/stat over the same interval, all cores:
 *          U = 1 - (idle + iowait) / total
 *
 *   bench_start(&b);     // just before the first fTPM command
 *   ... fTPM call(s) ...
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
	b->t0 = bench_now();
}

static inline void bench_stop(struct bench *b)
{
	if (!bench_on())
		return;
	b->t1 = bench_now();
	bench_cpu(&b->busy1, &b->total1);
}

static inline void bench_log(struct bench *b)
{
	FILE *f;

	if (!bench_on() || !(f = fopen(getenv("BENCH_OUT"), "a")))
		return;
	if (ftell(f) == 0)
		fprintf(f, "seq,t_ta_ns,busy_ticks,total_ticks\n");
	fprintf(f, "%u,%llu,%llu,%llu\n", b->seq++,
		(unsigned long long)(b->t1 - b->t0),
		b->busy1 - b->busy0, b->total1 - b->total0);
	fclose(f);
}

/* true once $BENCH_REQUESTS requests have been logged */
static inline int bench_done(struct bench *b)
{
	const char *n = getenv("BENCH_REQUESTS");

	return bench_on() && n && b->seq >= (unsigned)atoi(n);
}

#endif /* BENCH_H */