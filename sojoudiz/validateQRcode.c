
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"

/* Returns the value of a hex number */
uint8_t hex_val(char str){
	if(str >= '0' | str <= '9')
		return str-'0';
	else if(str >= 'A' | str <= 'Z')
		return str-'A'+10;
	else if(str >= 'a' | str <= 'z')
		return str - 'a' + 10;

	return -1;
}

/* Calculates the HMAC value */
void calculate_sha(uint8_t* secret, uint8_t* sha, uint8_t* message, int message_length){

//HMAC = H[(k xor opad) || H((k xor ipad) || M)];
	uint8_t new_secret[SHA1_BLOCKSIZE];

	int i;
	for(i = 0 ; i < 10 ; i++){
		new_secret[i] = secret[i];
	}

	for(i = 10 ; i < SHA1_BLOCKSIZE ; i++){
		new_secret[i] = 0x00;
	}

	uint8_t key_opad[SHA1_BLOCKSIZE];
	uint8_t key_ipad[SHA1_BLOCKSIZE];

	for(i = 0 ; i < SHA1_BLOCKSIZE ; i++){
		key_opad[i] = 0x5c ^ new_secret[i];
		key_ipad[i] = 0x36 ^ new_secret[i];
	}

  SHA1_INFO ctx;
  uint8_t sha_i[SHA1_DIGEST_LENGTH];
  sha1_init(&ctx);
  sha1_update(&ctx, key_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, message , message_length);
	sha1_final(&ctx, sha_i);

	//SHA1_INFO ctx;
	sha1_init(&ctx);
  sha1_update(&ctx, key_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, sha_i,SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, sha);

	return;


}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	/* Calculate the byte array of the secret hex */
	uint8_t secret[11];
	int i;
	char* ptr = secret_hex;
	for(i = 0; i < 10 ; i++){
		secret[i] = 16 * hex_val(*ptr) + (hex_val(*(ptr+1)));
		ptr = ptr+2;
	}
	secret[10] = '\0';

	/* byte array of the counter */
	uint8_t counter[8] = {0};
	counter[7] = 1;

	uint8_t sha[SHA1_DIGEST_LENGTH];
	calculate_sha(secret, sha, counter, 8);

	/* Truncates the HMAC and calculates the HOTP value*/
	int offset   =  sha[19] & 0xf ;
	int bin_code = (sha[offset]  & 0x7f) << 24| (sha[offset+1] & 0xff) << 16
	           | (sha[offset+2] & 0xff) <<  8
	           | (sha[offset+3] & 0xff) ;

		int hotp_val = bin_code % 1000000;

		/* Compare the calculated and received values of HOTP */
		int HOTP = atoi(HOTP_string);
    if (hotp_val == HOTP)
    	return 1;

    return 0;
}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
		/* Calculate the byte array of the secret hex */
		uint8_t secret[11];
		int i;
		char* ptr = secret_hex;
		for(i = 0; i < 10 ; i++){
			secret[i] = 16 * hex_val(*ptr) + (hex_val(*(ptr+1)));
			ptr = ptr+2;
		}
		secret[10] = '\0';

		/* byte array of timer */
		int curr_time = time(NULL)/30;
		uint8_t timer[8];
		for( i = 7; i >= 0 ; i--){
				timer[i] = curr_time & 0xff;
				curr_time >>= 8;
		}

		uint8_t sha[SHA1_DIGEST_LENGTH];
		calculate_sha(secret, sha, timer, 8);

		/* Truncates the HMAC and calculates the HOTP value*/
		int offset   =  sha[19] & 0xf ;
		int bin_code = (sha[offset]  & 0x7f) << 24| (sha[offset+1] & 0xff) << 16
							 | (sha[offset+2] & 0xff) <<  8
							 | (sha[offset+3] & 0xff) ;

			int totp_val = bin_code % 1000000;

			/* Compare the calculated and received values of HOTP */
			int TOTP = atoi(TOTP_string);
			if (totp_val == TOTP)
				return 1;

			return 0;
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
