/*
 * ra_ftpm_ca.c - remote-attestation relay (attester) for OP-TEE's fTPM.
 *
 * The CA is ONLY a relay: it never decides what is measured and never
 * sees a secret. It connects to the verifier once and stays connected.
 * Each time the verifier sends an attest command (nonce + file list):
 *   1. MEASURE into PCR 16: reset it, extend the nonce, then let the fTPM
 *      hash every file the verifier asked for and extend each hash
 *   2. ask the fTPM for a quote (PCRs 0-7 + 16 + the nonce, signed by AK)
 *   3. send the AK public key, the quote, the signature, the PCR values
 *      and the hash of each file (so the verifier can see which changed)
 *   4. print the verifier's answer, then wait for the next command
 * If the connection is lost, it reconnects automatically.
 *
 * PCRs 0-7 can't be reset from Linux, only extended. So even root in
 * Linux can make them wrong (-> FAIL) but never set them back to the
 * enrolled values. What goes into them is decided before Linux runs.
 *
 * Network messages are simply [4-byte big-endian length][data]:
 *   verifier -> CA : 'A' + nonce length (1 byte) + nonce + file list
 *                    (file list = paths separated by '\n')
 *   CA -> verifier : AK public key, quote, signature, PCR values,
 *                    file hashes (32 bytes each, in file-list order)
 *   verifier -> CA : verdict text
 *
 * Usage: ra_ftpm_ca <verifier-ip> <port>
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>


// For benchmarking
#include "bench.h"
static struct bench b;

#define CMD_ATTEST  'A'
#define MAX_CMD     4096                  /* max size of an attest command */
#define NUM_PCRS    9                     /* PCRs 0-7 and 16 */

#define IMA_LOG  "/sys/kernel/security/ima/binary_runtime_measurements"
#define MAX_LOG  (16u * 1024 * 1024)

static void check(TSS2_RC rc, const char *what)
{
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "%s failed: %s\n", what, Tss2_RC_Decode(rc));
		exit(1);
	}
}

/* ---------------- network: [length][data] ---------------- */

/* Returns 0 on success, -1 if the connection is gone. */
static int send_msg(int fd, const void *data, uint32_t len)
{
	uint32_t be = htonl(len);

	/* MSG_NOSIGNAL: don't crash if the verifier has gone away */
	if (send(fd, &be, 4, MSG_NOSIGNAL) != 4 ||
	    send(fd, data, len, MSG_NOSIGNAL) != (ssize_t)len)
		return -1;
	return 0;
}

/* Returns the number of bytes received, or -1 if the connection is gone. */
static int recv_msg(int fd, uint8_t *buf, uint32_t max)
{
	uint32_t be, len;

	if (recv(fd, &be, 4, MSG_WAITALL) != 4)
		return -1;
	len = ntohl(be);
	if (len > max || recv(fd, buf, len, MSG_WAITALL) != (ssize_t)len)
		return -1;
	return (int)len;
}

/* Returns the connection, or -1 if the verifier can't be reached. */
static int connect_to(const char *host, const char *port)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *ai;
	int fd;

	if (getaddrinfo(host, port, &hints, &ai) != 0)
		return -1;
	fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (fd >= 0 && connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
		close(fd);
		fd = -1;
	}
	freeaddrinfo(ai);
	return fd;
}

/* ---------------- measuring into PCRs ---------------- */

/* Reads PCRs 0-7 and 10 (SHA-256 bank) into out, in that order. */
static void read_pcrs(ESYS_CONTEXT *esys, uint8_t out[NUM_PCRS][32])
{
	const uint8_t sel[2][3] = { { 0xff, 0x00, 0x00 },   /* PCRs 0-7 */
                        		{ 0x00, 0x04, 0x00 } }; /* PCR 10   */

	int n = 0;

	for (int i = 0; i < 2; i++) {
		TPML_PCR_SELECTION want = {
			.count = 1,
			.pcrSelections[0] = { .hash = TPM2_ALG_SHA256,
					      .sizeofSelect = 3 },
		};
		TPML_PCR_SELECTION *got = NULL;
		TPML_DIGEST *vals = NULL;
		uint32_t counter;

		memcpy(want.pcrSelections[0].pcrSelect, sel[i], 3);
		check(Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE,
				    ESYS_TR_NONE, &want, &counter, &got, &vals),
		      "read PCRs");
		for (uint32_t k = 0; k < vals->count; k++)
			memcpy(out[n++], vals->digests[k].buffer, 32);
		Esys_Free(got);
		Esys_Free(vals);
	}
}

static uint8_t *read_ima_log(size_t *len)
{
	size_t cap = 65536, n = 0, r;
	uint8_t *buf = malloc(cap);
	FILE *f = fopen(IMA_LOG, "rb");

	if (!f || !buf) { perror("open IMA log"); exit(1); }
	while ((r = fread(buf + n, 1, cap - n, f)) > 0) {
		n += r;
		if (n == cap) {
			if (cap >= MAX_LOG) { fprintf(stderr, "IMA log too big\n"); exit(1); }
			buf = realloc(buf, cap *= 2);
		}
	}
	fclose(f);
	*len = n;
	return buf;
}

/* ---------------- main ---------------- */

int main(int argc, char *argv[])
{
	TSS2_TCTI_CONTEXT *tcti = NULL;
	ESYS_CONTEXT *esys = NULL;
	ESYS_TR ak = ESYS_TR_NONE;
	TPM2B_PUBLIC *ak_pub = NULL;
	uint8_t ak_buf[sizeof(TPM2B_PUBLIC)];
	size_t ak_len = 0;

	/*
	 * The AK: an ECC P-256 signing key. "Restricted" means the fTPM will
	 * only use it to sign things it made itself, like quotes. Created as a
	 * primary key, so the fTPM derives the SAME key every time.
	 */
	TPM2B_SENSITIVE_CREATE sensitive = { 0 };
	TPM2B_DATA outside = { 0 };
	TPML_PCR_SELECTION no_pcrs = { 0 };
	TPM2B_PUBLIC ak_template = {
		.publicArea = {
			.type = TPM2_ALG_ECC,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = TPMA_OBJECT_FIXEDTPM |
					    TPMA_OBJECT_FIXEDPARENT |
					    TPMA_OBJECT_SENSITIVEDATAORIGIN |
					    TPMA_OBJECT_USERWITHAUTH |
					    TPMA_OBJECT_RESTRICTED |
					    TPMA_OBJECT_SIGN_ENCRYPT,
			.parameters.eccDetail = {
				.symmetric.algorithm = TPM2_ALG_NULL,
				.scheme.scheme = TPM2_ALG_ECDSA,
				.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256,
				.curveID = TPM2_ECC_NIST_P256,
				.kdf.scheme = TPM2_ALG_NULL,
			},
		},
	};

	/* Which PCRs to quote: SHA-256 bank, PCRs 0-7 (boot) + 16 (files). */
	TPML_PCR_SELECTION pcrs = {
		.count = 1,
		.pcrSelections[0] = {
			.hash = TPM2_ALG_SHA256,
			.sizeofSelect = 3,
			.pcrSelect = { 0xff, 0x04, 0x00 },
		},
	};
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL }; /* use AK's */

	const char *host   = "127.0.0.1";
	const char *port   = "5000";
	const char *device = "/dev/tpmrm0";     /* default: Pi fTPM */

	if (argc >= 3) {
		host = argv[1];
		port = argv[2];
	}
	if (argc == 4) {
		device = argv[3];                   /* e.g. /dev/tpmrm0 on QEMU */
	} else if (argc != 1 && argc != 3) {
		fprintf(stderr, "Usage: %s [<verifier-ip> <port> [<tpm-device>]]\n", argv[0]);
		return 1;
	}

	/* build "device:<path>" for the TCTI */
	char module[128];
	snprintf(module, sizeof(module), "device:%s", device);

	setvbuf(stdout, NULL, _IOLBF, 0);   /* print each line immediately */

	/* Open the fTPM and create the AK once, at start-up. */
	check(Tss2_TctiLdr_Initialize(module, &tcti), "open TPM");
	check(Esys_Initialize(&esys, tcti, NULL), "Esys_Initialize");
	check(Esys_CreatePrimary(esys, ESYS_TR_RH_ENDORSEMENT,
				 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				 &sensitive, &ak_template, &outside, &no_pcrs,
				 &ak, &ak_pub, NULL, NULL, NULL),
	      "create AK");
	check(Tss2_MU_TPM2B_PUBLIC_Marshal(ak_pub, ak_buf, sizeof(ak_buf),
					   &ak_len), "encode AK");
	printf("fTPM ready, attestation key created\n");

	/* Outer loop: (re)connect to the verifier. */
	for (;;) {
		int fd = connect_to(host, port);

		if (fd < 0) {
			printf("Verifier not reachable, retrying in 3 s...\n");
			sleep(3);
			continue;
		}
		printf("Connected to verifier, waiting for commands\n");

		/* Inner loop: wait for a command, handle it, repeat. */
		for (;;) {
			static uint8_t msg[MAX_CMD + 1];
			char *path, *save;
			TPM2B_EVENT nonce_ev;
			uint8_t pcr_vals[NUM_PCRS][32];
			int nfiles = 0;
			TPML_DIGEST_VALUES *d = NULL;
			TPM2B_DATA nonce = { 0 };
			TPM2B_ATTEST *quote = NULL;
			TPMT_SIGNATURE *sig = NULL;
			uint8_t sig_buf[sizeof(TPMT_SIGNATURE)];
			size_t sig_len = 0;
			char verdict[256];
			int len, vlen, ok;
			uint8_t *log;
			size_t log_len, log_len2;

			/* 1. Wait for the next command (blocks here). */
			len = recv_msg(fd, msg, MAX_CMD);
			if (len < 0)
				break;                  /* connection lost */
			/* Command: 'A', nonce length, nonce, file list. */
			if (len < 3 || msg[0] != CMD_ATTEST || msg[1] == 0 ||
			    msg[1] > sizeof(nonce.buffer) || 2 + msg[1] > len) {
				printf("Ignoring unknown command\n");
				continue;
			}
			nonce.size = msg[1];
			memcpy(nonce.buffer, msg + 2, nonce.size);
			msg[len] = '\0';           /* ends the file list */
			printf("\nAttest command, %u-byte nonce\n", nonce.size);

			// Benchmark: First fTPM command of this request
			bench_start(&b);
			// ---------------------------------------
			do {
				log = read_ima_log(&log_len);
				check(Esys_Quote(esys, ak, ESYS_TR_PASSWORD, ESYS_TR_NONE,
						ESYS_TR_NONE, &nonce, &scheme, &pcrs,
						&quote, &sig), "quote");
				check(Tss2_MU_TPMT_SIGNATURE_Marshal(sig, sig_buf, sizeof(sig_buf),
									&sig_len), "encode signature");
				read_pcrs(esys, pcr_vals);
				free(read_ima_log(&log_len2));   /* did it grow meanwhile? */
				if (log_len2 != log_len) {       /* yes: retry */
					free(log); Esys_Free(quote); Esys_Free(sig);
					continue;
				}
				break;
			} while (1);

			bench_stop(&b);
			// ---------------------------------------

			printf("TPM signed a quote over PCRs 0-7 + 10\n");

			/* 4. Send AK, quote, signature, PCRs and file hashes. */
			ok = send_msg(fd, ak_buf, ak_len) == 0 &&
				send_msg(fd, quote->attestationData, 
					quote->size) == 0 &&
				send_msg(fd, sig_buf, sig_len) == 0 &&
				send_msg(fd, pcr_vals, sizeof(pcr_vals)) == 0 &&
				send_msg(fd, log, log_len) == 0;
			free(log);

			if (!ok)
				break;                  /* connection lost */

			// Benchmark: Log the benchmark
			bench_log(&b);
			// ---------------------------------------

			/* 5. Print the verdict. */
			vlen = recv_msg(fd, (uint8_t *)verdict,
					sizeof(verdict) - 1);
			if (vlen < 0)
				break;                  /* connection lost */
			verdict[vlen] = '\0';
			printf("Verifier says: %s\n", verdict);

			if (bench_done(&b)) {
				close(fd);
				return 0;
			}
		}

		close(fd);

		const char *enroll = getenv("ENROLL");
		if (bench_on() || (enroll && strcmp(enroll, "True") == 0)) {
			printf("Verifier disconnected, run complete\n");
			return 0;
		}

		printf("Connection lost, reconnecting in 3 s...\n");
		sleep(3);
	}
}