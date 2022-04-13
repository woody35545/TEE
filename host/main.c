#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

char context_file_name[20];
char option[10];
char context_file_input_buffer[100];



int main(int argc, char *argv[]) /* Arguemnt 받도록 변경하면 TEE 환경에서 TEEencrypt로 해당 바이너리 파일을 실행했을 때
Argument 들이 잘 넘어오는지 확인해야함. */
{

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[64] = {0,}; // input text 받을 array
	char ciphertext[64] = {0,}; // encrypt 된 text 저장할 array
	//int len = 64; // array length
	int len = 100;

	// Argument 제대로 들어오는지 확인
	
	for (int i=0; i<argc; i++){
		printf("[DEBUG] arv[%d]: %s\n", i, argv[i]);
	}

	// Argument Initializng
	if (argc >= 3){
		strcpy(option,argv[1]);
		strcpy(context_file_name, argv[2]);
	}



	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op)); // op 메모리 초기화

	/* 파라미터 타입 설정, 첫번째 파라미터만 사용하고 나머지 3개는 사용안함. */
    	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	//op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.buffer = context_file_input_buffer;
	op.params[0].tmpref.size = len;
	

	/* 파라미터 세팅 완료 */


	
	// Arguemnt 에 따라서 option 분류	
	if (strcmp(option, "-e") == 0){
		fs = fopen(context_file_name, "r");
		fgets(context_file_input_buffer,sizeof(context_file_input_buffer,fs);
		printf("[DEBUG] This is Encrypt Part\n");
		
		/* Request TA to Encrypt */

		printf("========================Encryption========================\n");
	
		memcpy(op.params[0].tmpref.buffer, context_file_input_buffer, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENCRYPT, &op, &err_origin);

		if (res != TEEC_SUCCESS) errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);

		printf("Ciphertext : %s\n", ciphertext);
	}	 


	if (strcmp(option, "-d") == 0){
		fs = fopen(context_file_name, "r");
		fgets(context_file_input_buffer,sizeof(context_file_input_buffer,fs);
		printf("[DEBUG] This is Decrypt Part\n");	
	
		
		printf("========================Decryption========================\n");
		memcpy(op.params[0].tmpref.buffer, context_file_input_buffer, len);
	
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DECRYPT, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS) errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);
	}
	
	// Option 분류 끝


	// 세션 종료

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
