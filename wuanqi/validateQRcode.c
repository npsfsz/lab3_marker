#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "lib/sha1.h"

#define IPAD 0x36
#define OPAD 0x5C

#define SECRET_KEY_LEN 20
#define SHA1_DIGEST_LENGTH 20
#define SHA1_BLOCK_LENGTH 64

static int
HMAC(uint8_t key[8], uint8_t counter[8], char * OTP_string ){
	
	int i;
	uint8_t key_ipad[64];
	uint8_t key_opad[64];

	//initializing ipad and opad with the key
	memset(key_ipad,0,64);
	memset(key_opad,0,64);
	memcpy(key_ipad,key,10);
	memcpy(key_opad,key,10);
	
	for (i=0;i<64;i++){
		key_ipad[i] ^= IPAD;
		key_opad[i] ^= OPAD;
		//printf("key: %d, %d",key_ipad[i], key_opad[i]);
	}
	
	//defining first_sha and second_sha
	SHA1_INFO ctx1, ctx2;
	uint8_t first_sha[SHA1_DIGEST_LENGTH];
	uint8_t second_sha[SHA1_DIGEST_LENGTH];
	
	//initializing first_sha
	sha1_init(&ctx1);
	sha1_update(&ctx1, key_ipad, SHA1_BLOCK_LENGTH);
	sha1_update(&ctx1, counter, 8);
	sha1_final(&ctx1, first_sha);
	
	//initializing second_sha
	sha1_init(&ctx2);
	sha1_update(&ctx2, key_opad, SHA1_BLOCK_LENGTH);
	sha1_update(&ctx2, first_sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, second_sha);
	
	//generate HMAC value and store in second_sha
	int offset = second_sha[19] & 0xf;
	int bin_code = (second_sha[offset] & 0x7f) << 24 | (second_sha[offset+1] & 0xff) << 16 | (second_sha[offset+2] & 0xff) << 8 | (second_sha[offset+3] & 0xff);
	int otp_value = bin_code %1000000;
	int OTP = atoi(OTP_string);
	if (otp_value == OTP) return 1;

	return (0);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int i;
	uint8_t key[10];
	uint8_t counter[8]={0,0,0,0,0,0,0,1};

	//coverting the secret_hex from a string array to a int key arrary half of its size
	for(i = 0; i < 10; i++){
		char hex[3]; 
		sprintf(hex,"%c%c",secret_hex[2*i],secret_hex[2*i+1]);
		key[i] = (int)strtol(hex, NULL, 16);
	}
	
	return HMAC(key, counter, HOTP_string);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{	
	int i,j;
	uint8_t key[10];
	uint8_t key_ipad[64];
	uint8_t key_opad[64];

	//coverting the secret_hex from a string array to a int key arrary half of its size
	for(i = 0; i < 10; i++){
		char hex[3]; 
		sprintf(hex,"%c%c",secret_hex[2*i],secret_hex[2*i+1]);
		key[i] = (int)strtol(hex, NULL, 16);
	}

	uint64_t second = time(NULL);
	uint64_t T0 = 0;
	uint64_t T = (second - T0)/30;
	uint8_t counter[8];
	
	for (i = 7, j = 0; i>=0; i--,j++ ){
		counter[i] = (uint8_t)(T >> (j*8));
	}
	
	return HMAC(key, counter, TOTP_string);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];
	char pad_secret_hex[SECRET_KEY_LEN+1];
	
	// assert secret over length 20, and pad 0 to its end if its length is less than 20 
	assert (strlen(secret_hex) <= 20);
	int secret_len = strlen(secret_hex);
	int i=0;
	if (secret_len >20){
		strncpy(pad_secret_hex, secret_hex,20);	
	}
	else 
		strncpy (pad_secret_hex, secret_hex,secret_len);
	for(i=secret_len; i<20; i++){
		pad_secret_hex[i] = '0';
	}
	pad_secret_hex[i]='\0';

	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(pad_secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(pad_secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
