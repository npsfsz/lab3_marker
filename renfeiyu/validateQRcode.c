#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include "lib/sha1.h"

#define chr2hex(c) ((c - '0' < 10) ? c - '0' : 10 + (c - 'A'))

uint8_t* convert2Hex(char* str){
	int len = strlen(str);
	uint8_t *data = malloc(len);
	memset(data, 0, len);
	int i;

	for(i = 0; i < len/2; i++){
		data[i] = chr2hex(str[i*2]) << 4 | chr2hex(str[i*2 + 1]);
	}
	return data;
}

void HMAC_SHA_1(uint8_t* data, int datalen, uint8_t* key, int keylen, uint8_t* result){
	SHA1_INFO info;
	uint8_t sha[SHA1_DIGEST_LENGTH];

	char ipad[SHA1_BLOCKSIZE];
	char opad[SHA1_BLOCKSIZE];
	
	memset(&ipad, 0x36, SHA1_BLOCKSIZE);
	memset(&opad, 0x5c, SHA1_BLOCKSIZE);

	int i;
	for(i = 0; i < keylen; i++){
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}

	sha1_init(&info);
	sha1_update(&info, ipad, SHA1_BLOCKSIZE);
	sha1_update(&info, data, datalen);
	sha1_final(&info, sha);

	sha1_init(&info);
	sha1_update(&info, opad, SHA1_BLOCKSIZE);
	sha1_update(&info, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&info, result);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string, int token)
{
	uint8_t text[8];
	int i;
	for(i = 7; i >= 0; i--, token >>= 8)
		text[i] = token & 0xFF;	

	uint8_t HMAC_val[SHA1_DIGEST_LENGTH];
	HMAC_SHA_1(text, 8, convert2Hex(secret_hex), 20, HMAC_val);

	int offset = HMAC_val[19] & 0xF;

	int binary = (HMAC_val[offset] & 0x7f) << 24
	| (HMAC_val[offset+1] & 0xff) << 16
	| (HMAC_val[offset+2] & 0xff) << 8
	| (HMAC_val[offset+3] & 0xff);

	return ((binary % 1000000) == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string, int token)
{
	return validateHOTP(secret_hex, TOTP_string, token);
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

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value, 1) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value, time(NULL) / 30) ? "valid" : "invalid");

	return(0);
}
