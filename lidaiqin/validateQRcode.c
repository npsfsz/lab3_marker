#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#define MOD  1000000
void
hmac_sha1(text, text_len, key, key_len, sha)
unsigned char* text;
int 					 text_len;
char* 				 key;
int 					 key_len;
uint8_t*       sha;

{
	SHA1_INFO ctx;
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	int i;
	bzero(k_ipad, sizeof (k_ipad));
	bzero(k_opad, sizeof (k_opad));
	bcopy(key, k_ipad, key_len);
	bcopy(key, k_opad, key_len);

	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, 64);
	sha1_update(&ctx, text, text_len);
	sha1_final(&ctx, sha);

	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, 64);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, sha);
}

int
getHOTP(uint8_t* hmac_result)
{
	int offset = hmac_result[19] & 0xf;
	int bin_code = (hmac_result[offset] & 0x7f) << 24
		| (hmac_result[offset+1] & 0xff) << 16
		| (hmac_result[offset+2] & 0xff) << 8
		| (hmac_result[offset+3] & 0xff) ;
	return bin_code % MOD;
}

uint8_t
toHex(char* c)
{
		uint8_t h1 = (c[0] >= '0' && c[0] <= '9') ? c[0] - '0' : c[0] - 'A' + 10;
		uint8_t h2 = (c[1] >= '0' && c[1] <= '9') ? c[1] - '0' : c[1] - 'A' + 10;

		uint8_t res = h1 * 16 + h2;
		return res;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t sha[SHA1_DIGEST_LENGTH];
	uint8_t counter[] = {0, 0, 0, 0, 0, 0, 0, 1};
	uint8_t secret_buf[10];
	int i;
	for (i = 0; i < 10; i++)
		secret_buf[i] = toHex(&secret_hex[2*i]);
	hmac_sha1(counter, 8, secret_buf, 10, sha);
	int res = (atoi(HOTP_string) == getHOTP(sha));
	return res;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t sha[SHA1_DIGEST_LENGTH];
	unsigned long long TIME = time(NULL) / 30;
	uint8_t counter[] = {(TIME >> 56) & 0xff, (TIME >> 48) & 0xff, (TIME >> 40) & 0xff, (TIME >> 32) & 0xff, (TIME >> 24) & 0xff, (TIME >> 16) & 0xff, (TIME >> 8) & 0xff, TIME & 0xff};
	uint8_t secret_buf[10];
	int i;
	for (i = 0; i < 10; i++)
		secret_buf[i] = toHex(&secret_hex[2*i]);
	hmac_sha1(counter, 8, secret_buf, 10, sha);
	int res = (atoi(TOTP_string) == getHOTP(sha));
	return res;
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
