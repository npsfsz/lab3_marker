#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"


void
hmac(uint8_t * secret_key, uint8_t *message, uint8_t *result) {
	uint8_t ipad[64];
	uint8_t opad[64];
	int i;

	/*
	printf("byte_array: ");
	for (i = 0; i < 8; i++) {
		printf("%02x ", message[i]);
	}
	printf("\n");
	*/
	


	memset(ipad, 0, sizeof(ipad));
	memcpy(ipad, secret_key, 10); // copy key on ipad

	// xor secret key with 0x36
	for (i = 0; i < 64; i++) {
		ipad[i] = ipad[i]^0x36;
	}

	uint8_t sha1_1[SHA1_DIGEST_LENGTH];

	SHA1_INFO ctx_1;
	sha1_init(&ctx_1);
	sha1_update(&ctx_1, ipad, 64);
	sha1_update(&ctx_1, message, 8);
	sha1_final(&ctx_1, sha1_1);

	memset(opad, 0, sizeof(opad));
	memcpy(opad, secret_key, 10); // copy key on opad

	for (i = 0; i < 64; i++) {
		opad[i] = opad[i]^0x5c;
	}

	uint8_t sha1_2[SHA1_DIGEST_LENGTH];

	SHA1_INFO ctx_2;
	sha1_init(&ctx_2);
	sha1_update(&ctx_2, opad, 64);
	sha1_update(&ctx_2, sha1_1, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx_2, sha1_2);
	strncpy(result, sha1_2, SHA1_DIGEST_LENGTH);

}

int
truncate(uint8_t *hmac_result) {
	// confirm that message from hmac is 20 bytes long
	//assert (hmac_result <= 20);

	/* taken from rfc4226 p7 */
	int offset = hmac_result[19] & 0xf;
	int bin_code = (hmac_result[offset] & 0x7f) << 24
		| (hmac_result[offset+1] & 0xff) << 16
		| (hmac_result[offset+2] & 0xff) << 8
		| (hmac_result[offset+3] & 0xff);

	bin_code = (int)bin_code % (int)(1000000);
	return bin_code;
}


static int
validateHOTP(uint8_t * secret_char, char * HOTP_string)
{
	uint8_t counter[8] = {0};
	counter[7] = 1;

	uint8_t hmac_sha1[SHA1_DIGEST_LENGTH];
	hmac(secret_char, counter, hmac_sha1);
	int hotp = truncate(hmac_sha1);
	
	if (hotp == atoi(HOTP_string))
		return (1);
	else
		return (0);
}

static int
validateTOTP(uint8_t * secret_char, char * TOTP_string)
{
	// Parse it from the URL
    long current_time = time(NULL)/30;

    uint8_t time_char[8];
    int i=0;
   	for (i = 7; i >= 0; i--) {
   		time_char[i] = current_time;
   		current_time >>= 8;
   	}

	char hmac_sha1[SHA1_DIGEST_LENGTH];
	hmac(secret_char, time_char, hmac_sha1);

	int totp = truncate(hmac_sha1);
	if (totp == atoi(TOTP_string))
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

	uint8_t secret_char[10];

	int i;
	for (i = 0; i < 20; i+=2) {
		sscanf(&secret_hex[i], "%2hhx", &secret_char[i/2]);
	}

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_char, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_char, TOTP_value) ? "valid" : "invalid");

	return(0);
}
