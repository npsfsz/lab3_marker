#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	//Convert secret key into binary form
	uint8_t hex_bits[64];
	char hex[3];
	int i;
	for (i = 0; i < 10; i++) {
		hex[0] = secret_hex[2 * i];
		hex[1] = secret_hex[2 * i + 1];
		hex[2] = '\0';
		hex_bits[i] = (unsigned int) strtoul(hex, NULL, 16);
	}

	//Pad rest of the secret key with zeros
	for (i = 10; i < 64; i++) {
		hex_bits[i] = '\x00';
	}

	//Counter (i.e. message) is 8-byte message (hardcoded to 1 for this lab)
	uint8_t counter[8];
	for (i = 0; i < 7; i++) {
		counter[i] = '\x00';
	}
	counter[7] = '\x01';

	//Compute input into inner hash ((K ^ ipad) || m)
	uint8_t hash_in1[72];
	for (i = 0; i < 64; i++) {
		hash_in1[i] = hex_bits[i] ^ '\x36';
	}
	for (i = 64; i < 72; i++) {
		hash_in1[i] = counter[i-64];
	}

	//Compute inner hash H((K ^ ipad) || m)
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, hash_in1, 72);
	sha1_final(&ctx, sha);

	//Compute input into outer hash ((K ^ opad) || inner_hash)
	uint8_t hash_in2[84];
	for (i = 0; i < 64; i++) {
		hash_in2[i] = hex_bits[i] ^ '\x5c';
	}
	for (i = 64; i < 84; i++) {
		hash_in2[i] = sha[i - 64];
	}

	//Compute outer hash HMAC = H((K ^ opad) || inner_hash)
	SHA1_INFO ctx2;
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx2);
	sha1_update(&ctx2, hash_in2, 84);
	sha1_final(&ctx2, hmac);

	//Truncate HMAC
	uint8_t trun_hmac[4];
	int offset = hmac[19] & 0xf;
	for (i = 0; i < 4; i++) {
		trun_hmac[i] = hmac[offset + i];
	}
	trun_hmac[0] = trun_hmac[0] & 0x7f;

	//Convert the truncated HMAC to long
	unsigned long hotp_long = trun_hmac[0] << 24 | trun_hmac[1] << 16 | trun_hmac[2] << 8 | trun_hmac[3];
	unsigned long hotp_value = hotp_long % 1000000;

	if (hotp_value == strtoul(HOTP_string, NULL, 10))
		return (1);
	else
		return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{	
	//Convert secret key into binary form
	uint8_t hex_bits[64];
	char hex[3];
	int i;
	for (i = 0; i < 10; i++) {
		hex[0] = secret_hex[2 * i];
		hex[1] = secret_hex[2 * i + 1];
		hex[2] = '\0';
		hex_bits[i] = (unsigned int) strtoul(hex, NULL, 16);
	}

	//Pad rest of the secret key with zeros
	for (i = 10; i < 64; i++) {
		hex_bits[i] = '\x00';
	}

	//Timer is 8-byte message used for hash
	uint8_t timer[8];
	time_t timer_value = (time(NULL) - 0) / 30; //Default T0 = 0, Period = 30
	for (i = 0; i < 8; i++) {
		timer[i] = (timer_value >> (56 - (i * 8))) & 0xff;
	}

	//Compute input into inner hash ((K ^ ipad) || m)
	uint8_t hash_in1[72];
	for (i = 0; i < 64; i++) {
		hash_in1[i] = hex_bits[i] ^ '\x36';
	}
	for (i = 64; i < 72; i++) {
		hash_in1[i] = timer[i-64];
	}

	//Compute inner hash H((K ^ ipad) || m)
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, hash_in1, 72);
	sha1_final(&ctx, sha);

	//Compute input into outer hash ((K ^ opad) || inner_hash)
	uint8_t hash_in2[84];
	for (i = 0; i < 64; i++) {
		hash_in2[i] = hex_bits[i] ^ '\x5c';
	}
	for (i = 64; i < 84; i++) {
		hash_in2[i] = sha[i - 64];
	}

	//Compute outer hash HMAC = H((K ^ opad) || inner_hash)
	SHA1_INFO ctx2;
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx2);
	sha1_update(&ctx2, hash_in2, 84);
	sha1_final(&ctx2, hmac);

	//Truncate HMAC
	uint8_t trun_hmac[4];
	int offset = hmac[19] & 0xf;
	for (i = 0; i < 4; i++) {
		trun_hmac[i] = hmac[offset + i];
	}
	trun_hmac[0] = trun_hmac[0] & 0x7f;

	//Convert the truncated HMAC to long
	unsigned long totp_long = trun_hmac[0] << 24 | trun_hmac[1] << 16 | trun_hmac[2] << 8 | trun_hmac[3];
	unsigned long totp_value = totp_long % 1000000;

	if (totp_value == strtoul(TOTP_string, NULL, 10))
		return (1);
	else
		return (0);
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
