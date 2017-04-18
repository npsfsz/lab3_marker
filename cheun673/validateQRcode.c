#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "lib/sha1.h"

static long dynamic_truncate(uint8_t * input){

	uint8_t offset = input[19] & 0x0f;
	return (
		((input[offset] & 0x7f) << 24) |
		((input[offset + 1] & 0xff) << 16) |
		((input[offset + 2] & 0xff) << 8) |
		((input[offset + 3] & 0xff))
	);
}

static int hex_str_to_bytes(char *hex, uint8_t *result) {
	// handling the input, change string to uint
	int secretLength = strlen(hex);

	int i;
	memset(result, 0, secretLength);

	for(i = 0 ; i < secretLength;i ++ ){
		uint8_t mynum = hex[i];
		uint8_t newnum = (mynum >= '0' && mynum <= '9')? mynum - '0' : mynum - 'A' + 10;
		if( (i%2) != 0){
			result[i/2] = result[i/2] | newnum;
		}
		else{
			newnum = newnum << 4;
			result[i/2] = result[i/2] | newnum;
		}
	}
}

static uint8_t *hmac_sha1(char *secret_hex, int secret_length, char *message, int message_length) {
	uint8_t key[SHA1_BLOCKSIZE];
	memset(key, 0, SHA1_BLOCKSIZE);
	memcpy(key, secret_hex, secret_length);

	uint8_t o_key_pad[65];	
	uint8_t i_key_pad[65];
	memset(o_key_pad, 0, sizeof(o_key_pad));
	memset(i_key_pad, 0, sizeof(i_key_pad));
	int i;
	for (i = 0; i < SHA1_BLOCKSIZE; i++) {
		o_key_pad[i] = key[i] ^ 0x5c;
		i_key_pad[i] = key[i] ^ 0x36;
	}

	SHA1_INFO ctx_inner;
	uint8_t sha_inner[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx_inner);

	sha1_update(&ctx_inner, i_key_pad, SHA1_BLOCKSIZE);
	sha1_update(&ctx_inner, message, message_length);
	sha1_final(&ctx_inner, sha_inner);

	SHA1_INFO ctx_outer;
	uint8_t *sha_outer = malloc(SHA1_DIGEST_LENGTH);
	sha1_init(&ctx_outer);

	sha1_update(&ctx_outer, o_key_pad, SHA1_BLOCKSIZE);
	sha1_update(&ctx_outer, sha_inner, 20);
	sha1_final(&ctx_outer, sha_outer);

	return sha_outer;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t secret[20];
	hex_str_to_bytes(secret_hex, secret);

	uint64_t moving_factor = 1;
	uint8_t counter[sizeof(moving_factor)];
	int i;
	for (i = 0; i < sizeof(counter); i++) {
		counter[i] = (moving_factor >> ((sizeof(moving_factor) - i - 1) * 8)) & 0xff;
	}
	uint8_t *hs = hmac_sha1(secret, 20, counter, sizeof(moving_factor));

	long token = dynamic_truncate(hs) % (1000000);

	return atol(HOTP_string) == token;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t secret[20];
	hex_str_to_bytes(secret_hex, secret);

	uint64_t moving_factor = time(NULL) / 30;
	uint8_t counter[sizeof(moving_factor)];
	int i;
	for (i = 0; i < sizeof(counter); i++) {
		counter[i] = (moving_factor >> ((sizeof(moving_factor) - i - 1) * 8)) & 0xff;
	}
	uint8_t *hs = hmac_sha1(secret, 20, counter, sizeof(moving_factor));

	printf("hs: ");
	for(i = 0;i < 20; i ++){
		printf("%x ", hs[i]);
	}
	printf("\n");

	long token = dynamic_truncate(hs) % (1000000);

	return atol(TOTP_string) == token;
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
