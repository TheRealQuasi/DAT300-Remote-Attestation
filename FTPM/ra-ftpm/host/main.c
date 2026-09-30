/*
 * ra_ftpm_ca.c - remote-attestation relay (attester) for OP-TEE's fTPM.
 *
 * Connects to the verifier ONCE and stays connected. It then waits for
 * commands. Each time the verifier sends an attest command with a nonce:
 *   1. ask the fTPM for a quote (PCRs 0-7 + the nonce, signed by the AK)
 *   2. send the AK public key, the quote and the signature back
 *   3. print the verifier's answer
 *   4. go back to waiting
 * If the connection is lost, it reconnects automatically.
 *
 * All checking is done by the verifier.
 *
 * Network messages are simply [4-byte big-endian length][data]:
 *   verifier -> CA : 'A' + nonce         (command: attest with this nonce)
 *   CA -> verifier : AK public key, quote, signature   (TPM wire format)
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

#define CMD_ATTEST 'A'

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

	/* Which PCRs to quote: SHA-256 bank, PCRs 0-7. */
	TPML_PCR_SELECTION pcrs = {
		.count = 1,
		.pcrSelections[0] = {
			.hash = TPM2_ALG_SHA256,
			.sizeofSelect = 3,
			.pcrSelect = { 0xff, 0x00, 0x00 },
		},
	};
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL }; /* use AK's */

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <verifier-ip> <port>\n", argv[0]);
		return 1;
	}

	/* Open the fTPM and create the AK once, at start-up. */
	check(Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &tcti), "open TPM");
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
		int fd = connect_to(argv[1], argv[2]);

		if (fd < 0) {
			printf("Verifier not reachable, retrying in 3 s...\n");
			sleep(3);
			continue;
		}
		printf("Connected to verifier, waiting for commands\n");

		/* Inner loop: wait for a command, handle it, repeat. */
		for (;;) {
			uint8_t msg[1 + sizeof(((TPM2B_DATA *)0)->buffer)];
			TPM2B_DATA nonce = { 0 };
			TPM2B_ATTEST *quote = NULL;
			TPMT_SIGNATURE *sig = NULL;
			uint8_t sig_buf[sizeof(TPMT_SIGNATURE)];
			size_t sig_len = 0;
			char verdict[256];
			int len, vlen;

			/* 1. Wait for the next command (blocks here). */
			len = recv_msg(fd, msg, sizeof(msg));
			if (len < 0)
				break;                  /* connection lost */
			if (len < 2 || msg[0] != CMD_ATTEST) {
				printf("Ignoring unknown command\n");
				continue;
			}

			/* The rest of the message is the nonce. */
			nonce.size = (UINT16)(len - 1);
			memcpy(nonce.buffer, msg + 1, nonce.size);
			printf("\nAttest command, %u-byte nonce\n", nonce.size);

			/* 2. Ask the fTPM for a quote over PCRs 0-7 + nonce. */
			check(Esys_Quote(esys, ak, ESYS_TR_PASSWORD,
					 ESYS_TR_NONE, ESYS_TR_NONE, &nonce,
					 &scheme, &pcrs, &quote, &sig),
			      "quote");
			check(Tss2_MU_TPMT_SIGNATURE_Marshal(sig, sig_buf,
							     sizeof(sig_buf),
							     &sig_len),
			      "encode signature");
			printf("fTPM signed a quote over PCRs 0-7\n");

			/* 3. Send AK, quote and signature back. */
			if (send_msg(fd, ak_buf, ak_len) < 0 ||
			    send_msg(fd, quote->attestationData,
				     quote->size) < 0 ||
			    send_msg(fd, sig_buf, sig_len) < 0) {
				Esys_Free(quote);
				Esys_Free(sig);
				break;                  /* connection lost */
			}
			Esys_Free(quote);
			Esys_Free(sig);

			/* 4. Print the verdict. */
			vlen = recv_msg(fd, (uint8_t *)verdict,
					sizeof(verdict) - 1);
			if (vlen < 0)
				break;                  /* connection lost */
			verdict[vlen] = '\0';
			printf("Verifier says: %s\n", verdict);
		}

		close(fd);
		printf("Connection lost, reconnecting in 3 s...\n");
		sleep(3);
	}
}