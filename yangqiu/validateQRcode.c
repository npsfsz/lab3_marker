#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

int hex_char_to_int(char hex)
{
	return (hex<='9') ? (hex-'0') : (hex-'A'+10);
}

void decode_ascii_hex(char* hex_str, char* result)
{
	int i, j;

	i = 0;
	j = 0;
	while (i < strlen(hex_str)/2) {
		int low, high;
		high = hex_char_to_int(hex_str[j]);
		j++;
		low = hex_char_to_int(hex_str[j]);
		j++;
		result[i] = low + (high << 4);
		i++;
	}
}

void sha1(char* key, char* data, int len, uint8_t* result)\
{
	SHA1_INFO ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, key, 10);
	// keep calling sha1_update if you have more data to hash...
	sha1_update(&ctx, data, len);
	sha1_final(&ctx, result);
}

uint64_t little_endian_to_big(uint64_t input)
{
	input = (input & 0x00000000FFFFFFFF) << 32 | (input & 0xFFFFFFFF00000000) >> 32;
	input = (input & 0x0000FFFF0000FFFF) << 16 | (input & 0xFFFF0000FFFF0000) >> 16;
	input = (input & 0x00FF00FF00FF00FF) << 8  | (input & 0xFF00FF00FF00FF00) >> 8;
	return input;
}

static int validate_hmac(char * secret_hex, uint64_t *expected, char * input)
{
	int i;
	SHA1_INFO ctx;
	int offset;
	int bin_code;
	int password_val;
	uint8_t ipad[64] = {0};
	uint8_t opad[64] = {0};
	uint8_t key[10] = {0};
	uint8_t result[SHA1_DIGEST_LENGTH];
	char ascii_result[7] = {0};

	decode_ascii_hex(secret_hex, key);
	memcpy(ipad, key, 10);
	memcpy(opad, key, 10);

	for (i = 0; i < 64; i++) {
		ipad[i] = ipad[i] ^ 0x36;
		opad[i] = opad[i] ^ 0x5c;
	}

	sha1_init(&ctx);
	sha1_update(&ctx, ipad, 64);
	sha1_update(&ctx, (uint8_t *)expected, 8);
	sha1_final(&ctx, result);

	sha1_init(&ctx);
	sha1_update(&ctx, opad, 64);
	sha1_update(&ctx, result, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, result);

	offset = result[19] & 0xf ;
	bin_code = (result[offset] & 0x7f) << 24
	| (result[offset+1] & 0xff) << 16
	| (result[offset+2] & 0xff) << 8
	| (result[offset+3] & 0xff);

	password_val = bin_code % 1000000;

	snprintf(ascii_result, 7, "%ld", password_val);

	//printf("result = %s\n", ascii_result);

	return strcmp(ascii_result, input) == 0;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint64_t counter = little_endian_to_big(1);

	return validate_hmac(secret_hex, &counter, HOTP_string);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint64_t counter = little_endian_to_big((uint64_t)time(NULL)/30);

	return validate_hmac(secret_hex, &counter, TOTP_string);
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

	//printf("sizeof(uint64_t) = %d", sizeof(uint64_t));

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
