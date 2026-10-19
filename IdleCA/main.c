/*
 * idle_bench.c - idle CPU-utilisation baseline for the attester device.
 *
 * Measures system-wide CPU utilisation U while NO remote attestation is
 * running, using the SAME bench.h instrumentation as the CA, so the U values
 * are directly comparable to the attestation benchmark.
 *
 * It samples /proc/stat over fixed time windows (not around a TPM request):
 * each "request" in the CSV is one sampling window. T_FTPM is therefore just
 * the window length and T_CPU is ~0 (this process sleeps) - those columns are
 * NOT meaningful here. Only U (busy_ticks / total_ticks) is the result.
 *
 * Build (same cross-compile as the CA, bench.h in the same dir):
 *   aarch64-linux-gnu-gcc -O2 -I<pi-sysroot>/usr/include -o idle_bench idle_bench.c
 *   (or just: gcc -O2 -o idle_bench idle_bench.c  if building natively)
 *
 * Run on the Pi, with the CA and verifier NOT running, system otherwise quiet:
 *   BENCH_OUT=idle.csv BENCH_REQUESTS=100 ./idle_bench [samples] [window_s]
 *     samples   : number of sampling windows (default 100; or BENCH_REQUESTS)
 *     window_s  : seconds per window (default 0.1)
 *
 * Then analyse with the usual benchmark analyzer - read the U line, ignore
 * T_FTPM/T_CPU:
 *   python3 ftpm-benchmark-analyzer.py idle.csv
 */

#include <stdlib.h>
#include <unistd.h>

#include "bench.h"

int main(int argc, char *argv[])
{
	struct bench b = { 0 };
	int samples = (argc > 1) ? atoi(argv[1]) : 100;
	double window = (argc > 2) ? atof(argv[2]) : 0.1;

	/* BENCH_REQUESTS, if set, caps the run just like the CA. */
	const char *req = getenv("BENCH_REQUESTS");
	if (req && atoi(req) > 0)
		samples = atoi(req);

	if (!getenv("BENCH_OUT")) {
		/* bench.h is a no-op without BENCH_OUT; refuse so we don't
		 * silently produce nothing. */
		fprintf(stderr, "set BENCH_OUT=<file> to record the idle U\n");
		return 1;
	}

	for (int i = 0; i < samples; i++) {
        if (i % 10 == 0)
            printf("idle_bench: sample %d/%d, window %.3f s\n", i, samples, window);
		bench_start(&b);                       /* reads busy/total @ t0 */
		usleep((useconds_t)(window * 1e6));    /* idle window */
		bench_stop(&b);                        /* reads busy/total @ t1 */
		bench_log(&b);                         /* one CSV row */
	}
	return 0;
}