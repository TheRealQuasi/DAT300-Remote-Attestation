#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pta_attestation.h>
#include <ra_demo_ta.h>
#include <string.h>

static const TEE_UUID pta_attestation_uuid = PTA_ATTESTATION_UUID;
static const TEE_UUID own_uuid = TA_RA_DEMO_UUID;

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				     TEE_Param params[4],
				     void **sess_ctx)
{
	(void)param_types;
	(void)params;
	(void)sess_ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)sess_ctx;
}

/*
 * Opens a session to the (secure-world-internal) Attestation PTA and asks
 * it to measure and sign *this* TA's own code/rodata, bound to the nonce
 * the CA gave us. This TA-to-PTA call is required: the PTA only allows a
 * TA to request its own digest, so a CA cannot skip us and call the PTA
 * directly for this operation (it CAN call the PTA directly for
 * GET_PUBKEY, since that command has no such restriction - see host/main.c).
 */
static TEE_Result get_evidence(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Param pta_params[4];
	uint32_t pta_pt;
	uint32_t ret_origin = 0;
	TEE_Result res;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_OpenTASession(&pta_attestation_uuid, 0, 0, NULL,
				 &sess, &ret_origin);
	if (res != TEE_SUCCESS)
		return res;

	memset(pta_params, 0, sizeof(pta_params));
	pta_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				  TEE_PARAM_TYPE_MEMREF_INPUT,
				  TEE_PARAM_TYPE_MEMREF_OUTPUT,
				  TEE_PARAM_TYPE_NONE);

	/* memref[0]: our own UUID, so the PTA knows which TA to measure */
	pta_params[0].memref.buffer = (void *)&own_uuid;
	pta_params[0].memref.size = sizeof(own_uuid);

	/* memref[1]: the nonce, forwarded straight from the CA */
	pta_params[1].memref.buffer = params[0].memref.buffer;
	pta_params[1].memref.size = params[0].memref.size;

	/* memref[2]: output buffer, also forwarded from the CA's buffer */
	pta_params[2].memref.buffer = params[1].memref.buffer;
	pta_params[2].memref.size = params[1].memref.size;

	res = TEE_InvokeTACommand(sess, 0, PTA_ATTESTATION_GET_TA_SHDR_DIGEST,
				   pta_pt, pta_params, &ret_origin);

	/* Report the real output size back to the CA either way */
	params[1].memref.size = pta_params[2].memref.size;

	TEE_CloseTASession(sess);

	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				       uint32_t param_types,
				       TEE_Param params[4])
{
	(void)sess_ctx;

	switch (cmd_id) {
	case TA_RA_CMD_GET_EVIDENCE:
		return get_evidence(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
