#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>

#include "lib/sha1.h"

int 
ascii_to_hex(char c)
{
	c = toupper(c);
	if (c >= 'A') return c - 'A' + 10;
	else return c - '0';
}

uint8_t*
string_to_8bit(char* secret_hex)
{
	// pad secret with 0s at the end
	char padded_secret[21];
	memset(padded_secret, '\0', 21);
	strcpy(padded_secret, secret_hex);

	int i;
	for(i = strlen(secret_hex); i < 20; i++) {
		padded_secret[i] = '0';
	}

	// convert string to 8 bit array
	uint8_t *secret_8bit = malloc(10);

	int j = 0;
	for(i = 0; i < 20; i += 2) {
		secret_8bit[j++] = 16*ascii_to_hex(padded_secret[i]) + ascii_to_hex(padded_secret[i+1]);
	}

	return secret_8bit;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t* secret_8bit = string_to_8bit(secret_hex);

	SHA1_INFO ctx;

	uint8_t inner_hash[SHA1_DIGEST_LENGTH];
	uint8_t outer_hash[SHA1_DIGEST_LENGTH];

	unsigned char k_ipad [SHA1_BLOCKSIZE];
	unsigned char k_opad [SHA1_BLOCKSIZE];

	memset(k_ipad, 0x36, SHA1_BLOCKSIZE);
	memset(k_opad, 0x5C, SHA1_BLOCKSIZE);

	int i;
	for(i = 0; i < 10; i++) {
		k_ipad[i] ^= secret_8bit[i];
		k_opad[i] ^= secret_8bit[i];
	}

	// 8 byte counter set to 1 as this password should only be used once
	uint8_t counter[8] = {0, 0, 0, 0, 0, 0, 0, 1}; 

	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, counter, 8);
	sha1_final(&ctx, inner_hash);

	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, inner_hash, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, outer_hash);

	// below code is taken from RFC4226
	int offset   =  outer_hash[19] & 0xf;

  	int bin_code = (outer_hash[offset]  & 0x7f) << 24
           | (outer_hash[offset+1] & 0xff) << 16
           | (outer_hash[offset+2] & 0xff) << 8
           | (outer_hash[offset+3] & 0xff);

    int result = bin_code % 1000000;

    free(secret_8bit);
	return (result == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t* secret_8bit = string_to_8bit(secret_hex);

	SHA1_INFO ctx;

	uint8_t inner_hash[SHA1_DIGEST_LENGTH];
	uint8_t outer_hash[SHA1_DIGEST_LENGTH];

	unsigned char k_ipad [SHA1_BLOCKSIZE];
	unsigned char k_opad [SHA1_BLOCKSIZE];

	memset(k_ipad, 0x36, SHA1_BLOCKSIZE);
	memset(k_opad, 0x5C, SHA1_BLOCKSIZE);

	int i;
	for(i = 0; i < 10; i++) {
		k_ipad[i] ^= secret_8bit[i];
		k_opad[i] ^= secret_8bit[i];
	}

	unsigned long T = time(NULL)/30;

	// use current UNIX time in hash calculation
	uint8_t time_counter[8] = 	{(T>>56)&0xff, 
								(T>>48)&0xff, 
								(T>>40)&0xff, 
								(T>>32)&0xff, 
								(T>>24)&0xff, 
								(T>>16)&0xff, 
								(T>>8)&0xff, 
								T&0xff}; 

	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, time_counter, 8);
	sha1_final(&ctx, inner_hash);

	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, inner_hash, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, outer_hash);

	// below code is taken from RFC6238
	int offset   =  outer_hash[19] & 0xf;

  	int bin_code = (outer_hash[offset]  & 0x7f) << 24
           | (outer_hash[offset+1] & 0xff) << 16
           | (outer_hash[offset+2] & 0xff) << 8
           | (outer_hash[offset+3] & 0xff);

    int result = bin_code % 1000000;

    free(secret_8bit);
	return (result == atoi(TOTP_string));
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
