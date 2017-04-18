#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#define PADDING_LEN 64
#define INNER_PAD 0x36
#define OUTER_PAD 0x5c
#define BYTE_LEN 10
#define COUNTER_LEN 8
#define FF 0xff
#define ZERO 0x00

void convert_to_hex(uint8_t unit_secret_len, uint8_t byte_secret_len, char * secret_hex, uint8_t * byte_secret)
{
	int i = 0;
	char *loc = secret_hex;
	while(i < (unit_secret_len / byte_secret_len)){
		sscanf(loc, "%2hhx", &byte_secret[i]);
		loc += 2;
		i++;
	}
}

static int validate(char * secret_hex, uint8_t * counter, char * string)
{
	uint8_t byte_secret[BYTE_LEN];
	uint8_t unit_secret_len = strlen(secret_hex);
	convert_to_hex(unit_secret_len, sizeof(byte_secret[0]), secret_hex, byte_secret);

    uint8_t inner_padding[PADDING_LEN];
    memset(inner_padding, 0, sizeof(inner_padding));
    memcpy(inner_padding, byte_secret, BYTE_LEN);

    uint8_t outer_padding[PADDING_LEN];
    memset(outer_padding, 0, sizeof(outer_padding));
    memcpy(outer_padding, byte_secret, BYTE_LEN);

	int i;
	for (i = 0; i < PADDING_LEN ; i++) {
		inner_padding[i] ^= INNER_PAD;
		outer_padding[i] ^= OUTER_PAD;
	}

	SHA1_INFO ctx;
	uint8_t inner_hash[SHA1_DIGEST_LENGTH];
	uint8_t outer_hash[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, inner_padding, PADDING_LEN);
	sha1_update(&ctx, counter, sizeof(counter));
	sha1_final(&ctx, inner_hash);

	sha1_init(&ctx);
	sha1_update(&ctx, outer_padding, PADDING_LEN);
	sha1_update(&ctx, inner_hash, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, outer_hash);

	int offset = outer_hash[SHA1_DIGEST_LENGTH - 1] & 0xf;
	long binary = ((outer_hash[offset] & 0x7f) << 24) | ((outer_hash[offset + 1] & 0xff) << 16)	| ((outer_hash[offset + 2] & 0xff) << 8) | ( outer_hash[offset + 3] & 0xff);

	long otp = binary % 1000000;
	int string_HOTP = atoi(string);

	if(otp == string_HOTP)
		return 1;
	else
		return 0;
}

static int validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t counter[8] = {0};
    counter[7] = 1;

	return validate(secret_hex, counter, HOTP_string);
}

static int validateTOTP(char * secret_hex, char * TOTP_string)
{
	int adj_time =  (int)(time(0)/30);
	uint8_t timer[8]; 
	timer[7] = (adj_time >> (8 * 0)) & FF;
	timer[6] = (adj_time >> (8 * 1)) & FF;
	timer[5] = (adj_time >> (8 * 2)) & FF;
	timer[4] = (adj_time >> (8 * 3)) & FF;

	int i;
	for (i = 0; i < 4; i++)
		timer[i] = ZERO;

	return validate(secret_hex, timer, TOTP_string);
}

int main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
