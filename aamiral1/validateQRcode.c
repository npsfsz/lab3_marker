#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>


#include "lib/sha1.h"


void convertToBinary(char * secret_hex, uint8_t * secret_uint8) {
	char * hex_chars = "0123456789ABCDEF";

	int i, j, k;
	int secret_int1, secret_int2;

	// iterate through secret_hex string (Note it is always 20 characters)
	for (i = 0, j = 0; i < 10; i++, j += 2) {

		secret_int1 = 0;
		secret_int2 = 0;


		for (k = 0; k < 16; k++) {
			if (secret_hex[j] == hex_chars[k]) {
				secret_int1 = k;
			}

			if (secret_hex[j+1] == hex_chars[k]) {
				secret_int2 = k;
			}

		}

		secret_uint8[i] = (secret_int1<<4) | (secret_int2);

	}
}

void createHOTP(uint8_t * message, uint8_t * key, uint8_t * result) {

	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];

	unsigned char k_ipad[SHA1_BLOCKSIZE+1] = "\0"; /* inner padding */
	unsigned char k_opad[SHA1_BLOCKSIZE+1] = "\0"; /* outer padding */

	/* Initialize inner and outer padding and copy key into them */
	memset( k_ipad, 0, SHA1_BLOCKSIZE); 
	memset( k_opad, 0, SHA1_BLOCKSIZE);
	memcpy( k_ipad, key, 10);
	memcpy( k_opad, key, 10);

	/* key length of 10 */
	int i = 0;
	for (i=0; i < 64; i++){
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/*
	* perform HMAC of inner pad + message
	*/
	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, 64);
	sha1_update(&ctx, message, 8);
	sha1_final(&ctx, sha);

	/*
	* perform HMAC of outer pad + HMAC of previous sha
	*/
	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, 64);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, result);

}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{

	uint8_t hmac_result[SHA1_DIGEST_LENGTH];

	/* HMAC-SHA-1(K,C) Counter is our message */
	uint8_t counter[] = {0,0,0,0,0,0,0,1};
	uint8_t secret_byte_array[10];

	convertToBinary(secret_hex, secret_byte_array);

	createHOTP(counter, secret_byte_array, hmac_result);

	int offset = hmac_result[19] & 0xf ;
	int bin_code = (hmac_result[offset] & 0x7f) << 24
	 | (hmac_result[offset+1] & 0xff) << 16
	 | (hmac_result[offset+2] & 0xff) << 8
	 | (hmac_result[offset+3] & 0xff) ;

	 int htop = bin_code % 1000000;

	 // printf("htop is ....  %d\n", htop);

	 if (htop == atoi(HOTP_string)) {
	 	return 1;
	 }

	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t hmac_result[SHA1_DIGEST_LENGTH];

	uint8_t time_steps[8];
	uint8_t secret_byte_array[10];

	time_t current_time = time(NULL);
	int T = ((int)current_time)/30;
	// printf("T: %ld %x\n", T, current_time);

	int i;

	for (i = 7; i >= 0; i--) {
		time_steps[i] = T;
		/* Convert current_time/30 into byte[] array */
		T >>= 8;
	}

	// printf("time %x\n", time_steps[7]);

	convertToBinary(secret_hex, secret_byte_array);

	createHOTP(time_steps, secret_byte_array, hmac_result);

	int offset = hmac_result[19] & 0xf ;
	int bin_code = (hmac_result[offset] & 0x7f) << 24
	 | (hmac_result[offset+1] & 0xff) << 16
	 | (hmac_result[offset+2] & 0xff) << 8
	 | (hmac_result[offset+3] & 0xff) ;

	 int totp = bin_code % 1000000;

	 // printf("totp is ....  %d\n", totp);

	 if (totp == atoi(TOTP_string)) {
	 	return 1;
	 }

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
