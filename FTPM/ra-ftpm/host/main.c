/*
 * ra_ftpm_ca.c - simple remote-attestation relay for OP-TEE's fTPM.
 *
 * The CA only passes things along:
 *   1. connect to the verifier and receive its nonce
 *   2. ask the fTPM for a quote (PCRs 0-7 + the nonce, signed by the AK)
 *   3. send the AK public key, the quote and the signature back
 *   4. print the verifier's answer
 *
 * All checking is done by the verifier.
 *
 * Network messages are simply [4-byte big-endian length][data]:
 *   verifier -> CA : nonce
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

static void check(TSS2_RC rc, const char *what)
{
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "%s failed: %s\n", what, Tss2_RC_Decode(rc));
		exit(1);
	}
}

/* ---------------- network: [length][data] ---------------- */

static void send_msg(int fd, const void *data, uint32_t len)
{
	uint32_t be = htonl(len);

	if (send(fd, &be, 4, 0) != 4 ||
	    send(fd, data, len, 0) != (ssize_t)len) {
		perror("send");
		exit(1);
	}
}

static uint32_t recv_msg(int fd, uint8_t *buf, uint32_t max)
{
	uint32_t be, len;

	if (recv(fd, &be, 4, MSG_WAITALL) != 4) {
		fprintf(stderr, "verifier closed the connection\n");
		exit(1);
	}
	len = ntohl(be);
	if (len > max || recv(fd, buf, len, MSG_WAITALL) != (ssize_t)len) {
		fprintf(stderr, "bad message from verifier\n");
		exit(1);
	}
	return len;
}

static int connect_to(const char *host, const char *port)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *ai;
	int fd;

	if (getaddrinfo(host, port, &hints, &ai) != 0) {
		fprintf(stderr, "cannot resolve %s\n", host);
		exit(1);
	}
	fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (fd < 0 || connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
		perror("connect");
		exit(1);
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
	TPM2B_ATTEST *quote = NULL;
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_DATA nonce = { 0 };
	uint8_t ak_buf[sizeof(TPM2B_PUBLIC)], sig_buf[sizeof(TPMT_SIGNATURE)];
	size_t ak_len = 0, sig_len = 0;
	char verdict[256];
	int fd;

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

	/* 1. Get the nonce from the verifier. */
	fd = connect_to(argv[1], argv[2]);
	nonce.size = recv_msg(fd, nonce.buffer, sizeof(nonce.buffer));
	printf("Got %u-byte nonce from verifier\n", nonce.size);

	/* 2. Ask the fTPM for a quote. */
	check(Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &tcti), "open TPM");
	check(Esys_Initialize(&esys, tcti, NULL), "Esys_Initialize");

	check(Esys_CreatePrimary(esys, ESYS_TR_RH_ENDORSEMENT,
				 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				 &sensitive, &ak_template, &outside, &no_pcrs,
				 &ak, &ak_pub, NULL, NULL, NULL),
	      "create AK");

	check(Esys_Quote(esys, ak, ESYS_TR_PASSWORD, ESYS_TR_NONE,
			 ESYS_TR_NONE, &nonce, &scheme, &pcrs,
			 &quote, &sig),
	      "quote");
	printf("fTPM signed a quote over PCRs 0-7\n");

	/* Turn the key and signature into bytes (TPM wire format). */
	check(Tss2_MU_TPM2B_PUBLIC_Marshal(ak_pub, ak_buf, sizeof(ak_buf),
					   &ak_len), "encode AK");
	check(Tss2_MU_TPMT_SIGNATURE_Marshal(sig, sig_buf, sizeof(sig_buf),
					     &sig_len), "encode signature");

	/* 3. Send everything back. */
	send_msg(fd, ak_buf, ak_len);
	send_msg(fd, quote->attestationData, quote->size);
	send_msg(fd, sig_buf, sig_len);

	/* 4. Print the verdict. */
	verdict[recv_msg(fd, (uint8_t *)verdict, sizeof(verdict) - 1)] = '\0';
	printf("Verifier says: %s\n", verdict);

	Esys_FlushContext(esys, ak);
	Esys_Free(ak_pub);
	Esys_Free(quote);
	Esys_Free(sig);
	Esys_Finalize(&esys);
	Tss2_TctiLdr_Finalize(&tcti);
	close(fd);
	return 0;
}