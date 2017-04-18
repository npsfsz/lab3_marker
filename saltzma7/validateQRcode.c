#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"

void createKey(char * s_hex, uint8_t * int_key[64]);

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	SHA1_INFO ctx;

	uint8_t sha[SHA1_DIGEST_LENGTH];
	uint8_t * key1 = malloc(64 * sizeof(uint8_t));
	uint8_t * key2 = malloc(64 * sizeof(uint8_t));
	uint8_t counter[8];
	bzero(counter, 8);
	counter[7] = 1;
	int i;

	//reconstruct one-time password value as an integer
	int HOTP_val = 0;

	//48 is ASCII value of zero
	for (i = 0; i < 6; i++) {
		HOTP_val += (HOTP_string[i]-48) * (int)pow(10, 5-i);
	}

	//pad the key and create the two subkeys
	createKey(secret_hex, &key1);
	createKey(secret_hex, &key2);

	for (i = 0; i < 64; i++) {
		key1[i] = key1[i] ^ 0x36;
		key2[i] = key2[i] ^ 0x5c;
	}

	sha1_init(&ctx);
	sha1_update(&ctx, key1, 64);
	sha1_update(&ctx, counter, 8);
	sha1_final(&ctx, sha);

	sha1_init(&ctx);
	sha1_update(&ctx, key2, 64);
	sha1_update(&ctx, sha, 20);
	sha1_final(&ctx, sha);

	int offset = sha[19] & 0x0F;
	int bin_code = (sha[offset] & 0x7F) << 24
		| (sha[offset + 1] & 0xFF) << 16
		| (sha[offset + 2] & 0xFF) << 8
		| (sha[offset + 3] & 0xFF);

	//printf("HOTP result: %d\n", bin_code % 1000000);
	return (bin_code % 1000000) == HOTP_val;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	SHA1_INFO ctx;

	uint8_t sha[SHA1_DIGEST_LENGTH];
	uint8_t *key1 = malloc(64 * sizeof(uint8_t));
	uint8_t *key2 = malloc(64 * sizeof(uint8_t));
	int i;
	time_t counter = time(NULL);
	uint8_t hash_counter[8];

	if (counter == -1){
		printf("Error getting system time, aborting");
		return -1;
	}

	counter /= 30;
	int byte_shift;
	for (i = 0; i < 8; i++) {
		byte_shift = 8*i;
		hash_counter[7-i] = counter>>byte_shift;
	}
	//reconstruct one-time password value as an integer
	int TOTP_val = 0;

	//48 is ASCII value of zero
	for (i = 0; i < 6; i++) {
		TOTP_val += (TOTP_string[i]-48) * (int)pow(10, 5-i);
	}

	printf("%d\n", TOTP_val);

	//pad the key and create the two subkeys
	createKey(secret_hex, &key1);
	createKey(secret_hex, &key2);


	for (i = 0; i < 64; i++) {
		key1[i] = key1[i] ^ 0x36;
		key2[i] = key2[i] ^ 0x5c;
	}

	sha1_init(&ctx);
	sha1_update(&ctx, key1, 64);
	sha1_update(&ctx, hash_counter, 8);
	sha1_final(&ctx, sha);

	sha1_init(&ctx);
	sha1_update(&ctx, key2, 64);
	sha1_update(&ctx, sha, 20);
	sha1_final(&ctx, sha);

	int offset = sha[19] & 0x0F;
	int bin_code = (sha[offset] & 0x7F) << 24
		| (sha[offset + 1] & 0xFF) << 16
		| (sha[offset + 2] & 0xFF) << 8
		| (sha[offset + 3] & 0xFF);

	//printf("TOTP result: %6d\n", bin_code % 1000000);
	return (bin_code % 1000000) == TOTP_val;
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

	printf("\nSecret (Hex): %s\nHOTP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}

void createKey(char * s_hex, uint8_t * int_hex[64]) {
	int i;
	bzero(*int_hex, 10);
	for (i = 0; i < 20; i++) {
		char c = s_hex[i];
		uint8_t c_mask;
		switch (c) {
			case '1': 
				c_mask = 0x01;
				break;
			case '2':
				c_mask = 0x02;
				break;
			case '3': 
				c_mask = 0x03;
				break;
			case '4':
				c_mask = 0x04;
				break;
			case '5':
				c_mask = 0x05;
				break;
			case '6':
				c_mask = 0x06;
				break;
			case '7':
				c_mask = 0x07;
				break;
			case '8':
				c_mask = 0x08;
				break;
			case '9':
				c_mask = 0x09;
				break;
			case 'A':
				c_mask = 0x0A;
				break;
			case 'B':
				c_mask = 0x0B;
				break;
			case 'C':
				c_mask = 0x0C;
				break;
			case 'D':
				c_mask = 0x0D;
				break;
			case 'E':
				c_mask = 0x0E;
				break;
			case 'F':
				c_mask = 0x0F;
				break;
			case '0':
				c_mask = 0x00;
				break;
		}
		if (i % 2 == 1) {
			(*int_hex)[i/2] = (*int_hex)[i/2] ^ c_mask;
		}
		else {
			(*int_hex)[i/2] = (*int_hex)[i/2] ^ c_mask << 4;
		}
	}
	return;
}
