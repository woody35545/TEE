#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[64] = {0,}; // input text 받을 array
	char ciphertext[64] = {0,}; // encrypt 된 text 저장할 array
	int len = 64; // array length
	
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);


	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	printf("========================Encryption========================\n");
	printf("Please Input Plaintext : ");
	scanf("%[^\n]s",plaintext);
	memcpy(op.params[0].tmpref.buffer, plaintext, len);

	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENCRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	printf("Ciphertext : %s\n", ciphertext);

	printf("========================Decryption========================\n");
	printf("Please Input Ciphertext : ");
	getchar();
	scanf("%[^\n]s",ciphertext);

	memcpy(op.params[0].tmpref.buffer, ciphertext, len);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DECRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	printf("Plaintext : %s\n", plaintext);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
