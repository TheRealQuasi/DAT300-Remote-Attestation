#ifndef TA_RA_DEMO_H
#define TA_RA_DEMO_H

/*
 * This UUID is already deployed and working in the reference environment
 * this package was built and tested against. If you fork this into your
 * own project alongside other custom TAs, generate a fresh one instead:
 *
 *     uuidgen
 *
 * and update BOTH this file (struct form below) and ta/Makefile (BINARY,
 * dashed string form) to match - they must be the same UUID or the build
 * will produce a TA the CA can never find.
 */
#define TA_RA_DEMO_UUID \
	{ 0xbb9a73d7, 0x684b, 0x4785, \
		{ 0x9e, 0x39, 0x06, 0xbf, 0xaa, 0xb9, 0xa2, 0xef } }

/*
 * TA_RA_CMD_GET_EVIDENCE - ask the TA to produce remote-attestation
 * evidence for itself, covering a caller-supplied nonce.
 *
 * [in]  memref[0]  Nonce (opaque bytes, caller-chosen, any length > 0)
 * [out] memref[1]  Evidence buffer. First 32 bytes = SHA-256 digest of
 *                   this TA's own signed header (code + rodata
 *                   measurement, taken from the TA's shdr::hash at load
 *                   time). Remaining bytes = RSASSA-PSS-SHA256 signature
 *                   over SHA256(nonce || digest), produced by OP-TEE's
 *                   built-in Attestation PTA using a key that never
 *                   leaves secure world.
 */
#define TA_RA_CMD_GET_EVIDENCE 0

/*
 * --- CA-side mirror of optee_os's pta_attestation.h ---
 *
 * optee_os's real pta_attestation.h (which ra_demo_ta.c includes
 * directly) lives in the TA dev-kit only. It is NOT exported to
 * normal-world builds via libteec, so host/main.c cannot #include it -
 * doing so fails with "pta_attestation.h: No such file or directory"
 * at CA compile time, even though the TA compiles fine with the same
 * include.
 *
 * The two constants the CA actually needs (the PTA's UUID, and its
 * GET_PUBKEY command number) are duplicated here under different names
 * so there's no collision with the real macros the TA side uses.
 *
 * Source of truth: optee_os core/pta/attestation.c and
 * lib/libutee/include/pta_attestation.h
 */
#define RA_DEMO_PTA_ATTESTATION_UUID \
	{ 0x39800861, 0x182a, 0x4720, \
		{ 0x9b, 0x67, 0x2b, 0xcd, 0x62, 0x2b, 0xc0, 0xb5 } }
#define RA_DEMO_PTA_ATTESTATION_GET_PUBKEY 0x0

#endif /* TA_RA_DEMO_H */
