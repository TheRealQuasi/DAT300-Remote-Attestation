#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include <ra_demo_ta.h>

#define PUBKEY_EXP_MAX 512
#define PUBKEY_MOD_MAX 512
#define EVIDENCE_MAX   1024

static void save_to_file(const char *path, const void *buf, size_t len)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		err(1, "fopen %s", path);
	if (fwrite(buf, 1, len, f) != len)
		err(1, "fwrite %s", path);
	fclose(f);
	printf("  wrote %s (%zu bytes)\n", path, len);
}

/*
 * Fetch the Attestation PTA's public key directly - no TA mediation
 * needed for this call, unlike GET_EVIDENCE below. In a real deployment
 * this only needs to happen once; the result is the trust anchor an
 * offline verifier checks signatures against.
 */
static void cmd_pubkey(const char *outdir)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID pta_uuid = RA_DEMO_PTA_ATTESTATION_UUID;
	TEEC_Result res;
	uint32_t err_origin;
	uint8_t exp[PUBKEY_EXP_MAX] = { 0 };
	uint8_t mod[PUBKEY_MOD_MAX] = { 0 };
	char path[512];

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &pta_uuid, TEEC_LOGIN_PUBLIC,
				NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession(attestation PTA) failed 0x%x origin 0x%x",
		     res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_VALUE_OUTPUT,
					  TEEC_NONE);
	op.params[0].tmpref.buffer = exp;
	op.params[0].tmpref.size = sizeof(exp);
	op.params[1].tmpref.buffer = mod;
	op.params[1].tmpref.size = sizeof(mod);

	res = TEEC_InvokeCommand(&sess, RA_DEMO_PTA_ATTESTATION_GET_PUBKEY,
				  &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "GET_PUBKEY failed 0x%x origin 0x%x", res, err_origin);

	printf("Public key retrieved:\n");
	printf("  exponent: %u bytes\n", op.params[0].tmpref.size);
	printf("  modulus:  %u bytes\n", op.params[1].tmpref.size);
	printf("  sig alg:  0x%x (should be TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256)\n",
	       op.params[2].value.a);

	snprintf(path, sizeof(path), "%s/pubkey_exp.bin", outdir);
	save_to_file(path, exp, op.params[0].tmpref.size);
	snprintf(path, sizeof(path), "%s/pubkey_mod.bin", outdir);
	save_to_file(path, mod, op.params[1].tmpref.size);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}

/*
 * Request attestation evidence, bound to a caller-chosen nonce, for our
 * own TA. This goes through ra_demo TA (not the PTA directly), since only
 * the TA itself is allowed to ask the PTA to measure it.
 */
static void cmd_attest(const char *nonce_str, const char *outdir)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID ta_uuid = TA_RA_DEMO_UUID;
	TEEC_Result res;
	uint32_t err_origin;
	uint8_t evidence[EVIDENCE_MAX] = { 0 };
	char path[512];

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &ta_uuid, TEEC_LOGIN_PUBLIC,
				NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession(ra_demo TA) failed 0x%x origin 0x%x",
		     res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)nonce_str;
	op.params[0].tmpref.size = strlen(nonce_str);
	op.params[1].tmpref.buffer = evidence;
	op.params[1].tmpref.size = sizeof(evidence);

	res = TEEC_InvokeCommand(&sess, TA_RA_CMD_GET_EVIDENCE, &op,
				  &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "GET_EVIDENCE failed 0x%x origin 0x%x", res, err_origin);

	printf("Evidence retrieved: %u bytes (32-byte digest + signature)\n",
	       op.params[1].tmpref.size);

	snprintf(path, sizeof(path), "%s/evidence.bin", outdir);
	save_to_file(path, evidence, op.params[1].tmpref.size);
	snprintf(path, sizeof(path), "%s/nonce.bin", outdir);
	save_to_file(path, nonce_str, strlen(nonce_str));

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s pubkey [outdir]\n"
		"      Fetch the Attestation PTA's public key once.\n"
		"  %s attest <nonce-string> [outdir]\n"
		"      Request signed evidence for this TA, bound to <nonce-string>.\n"
		"\n"
		"outdir defaults to /mnt/host (the 9p share to your Ubuntu host),\n"
		"so the verifier script can read the files without extra copying.\n",
		prog, prog);
}

int main(int argc, char *argv[])
{
	const char *outdir = "/mnt/host";

	if (argc == 2 && strcmp(argv[1], "pubkey") == 0) {
		cmd_pubkey(outdir);
	} else if (argc == 3 && strcmp(argv[1], "pubkey") == 0) {
		cmd_pubkey(argv[2]);
	} else if (argc == 3 && strcmp(argv[1], "attest") == 0) {
		cmd_attest(argv[2], outdir);
	} else if (argc == 4 && strcmp(argv[1], "attest") == 0) {
		cmd_attest(argv[2], argv[3]);
	} else {
		usage(argv[0]);
		return 1;
	}
	return 0;
}
