#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>

#include "lib/sha1.h"

uint8_t * convertStringToByteArray(char * str) {
	uint8_t str_len = strlen(str);
	uint8_t * bytearray = malloc(str_len/2);
	int i;
	for (i = 0; i < (str_len / 2); i++) {
			sscanf(str + 2*i, "%02x", &bytearray[i]);
	}
	return bytearray;
}

void hmacSHA1(uint8_t * key, int key_length, uint8_t * text, int text_length, uint8_t * output) {
	/*
	SHA1(K XOR opad, SHA1(K XOR ipad, text))
	*/
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	int i;

	unsigned char k_ipad[SHA1_BLOCKSIZE]; /* inner padding -key XORd with ipad*/
	unsigned char k_opad[SHA1_BLOCKSIZE]; /* outer padding -key XORd with opad*/

	/* start out by storing key in pads */
	bzero( k_ipad, sizeof k_ipad);
	bzero( k_opad, sizeof k_opad);
	bcopy( key, k_ipad, key_length);
	bcopy( key, k_opad, key_length);
	/* XOR key with ipad and opad values */
	for (i=0; i<SHA1_BLOCKSIZE; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	// Perform inner SHA1
	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, text, text_length);
	sha1_final(&ctx, sha);

	// Perform outer SHA1
	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, output);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{

	uint8_t * byteArrayKey = convertStringToByteArray(secret_hex);
	// Counter value
	uint8_t text[8] = {0, 0, 0, 0, 0, 0, 0, 1};

	// Step 1: Generate an HMAC-SHA-1 value
	uint8_t hmac_result[SHA1_DIGEST_LENGTH];
	hmacSHA1(byteArrayKey, 10, text, 8, hmac_result);

	// Step 2: Generate a 6-byte string (Dynamic Truncation)
	int offset   =  hmac_result[19] & 0xf ;
	int bin_code = (hmac_result[offset]  & 0x7f) << 24
		 | (hmac_result[offset+1] & 0xff) << 16
		 | (hmac_result[offset+2] & 0xff) <<  8
		 | (hmac_result[offset+3] & 0xff) ;

	// Step 3: Compute an HOTP value
	int finalValue = bin_code % 1000000;
	return (finalValue == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int X = 30;
	int T0 = 0; // Don't really need this tbh
	int T = (time(NULL) - T0)/X;


	uint8_t * byteArrayKey = convertStringToByteArray(secret_hex);
	// Counter value
	uint8_t text[8];
	int i;
	for (i = 8; i--; T >>= 8) {
		text[i] = T;
	}

	// Step 1: Generate an HMAC-SHA-1 value
	uint8_t hmac_result[SHA1_DIGEST_LENGTH];
	hmacSHA1(byteArrayKey, 10, text, 8, hmac_result);

	// Step 2: Generate a 6-byte string (Dynamic Truncation)
	int offset   =  hmac_result[19] & 0xf ;
	int bin_code = (hmac_result[offset]  & 0x7f) << 24
		 | (hmac_result[offset+1] & 0xff) << 16
		 | (hmac_result[offset+2] & 0xff) <<  8
		 | (hmac_result[offset+3] & 0xff) ;

	// Step 3: Compute an HOTP value
	int finalValue = bin_code % 1000000;
	return (finalValue == atoi(TOTP_string));
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
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
