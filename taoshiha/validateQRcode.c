#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"

void generateHMAC(uint8_t * key, uint8_t key_len, uint8_t *counter, uint8_t *result ){

	int i;
	uint8_t ipad[65];
	uint8_t opad[65];
	
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
	memcpy(ipad, key, key_len);
	memcpy(opad, key, key_len);

	for(  i = 0; i < 64; i++){
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	SHA1_INFO ctx;
	uint8_t i_sha[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, ipad, 64);
	sha1_update(&ctx, counter, sizeof(counter));
	sha1_final(&ctx, i_sha);

	SHA1_INFO ctx2;
	
	sha1_init(&ctx2);
	sha1_update(&ctx2, opad, 64);
	sha1_update(&ctx2, i_sha, sizeof(i_sha));
	sha1_final(&ctx2, result);

}



static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int i;

	char * key = secret_hex;
 	uint8_t key_len = strlen(secret_hex); //should be 20

	// generating the counter 
  	uint8_t counter[] = {0,0,0,0,0,0,0,1};

	// converting the char to binary
	uint8_t secret_byte[10];
	for(i=0; i<	(key_len/2); i++)
	{
       		 sscanf(secret_hex + 2*i, "%02x", &secret_byte[i]);	
	} 

	uint8_t hmac[SHA1_DIGEST_LENGTH];
	generateHMAC(secret_byte, key_len/2, counter, hmac);

	int offset = hmac[19] & 0xf;
	int binary = ((hmac[offset] & 0x7f) << 24) | 
			((hmac[offset + 1] & 0xff) << 16) |
			((hmac[offset + 2] & 0xff) << 8)  |
			(hmac[offset + 3] & 0xff); 

	long otp = binary % 1000000;
	int HOTP = atoi(HOTP_string);
	if (otp == HOTP) return 1;
	else return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int i;
	char * key = secret_hex;
 	uint8_t key_len = strlen(secret_hex); //should be 20

	// converting the char to binary
	uint8_t secret_byte[10];
	for( i=0; i<	(key_len/2); i++)
	{
       		 sscanf(secret_hex + 2*i, "%02x", &secret_byte[i]);	
	} 

	int T = ((int)time(NULL))/30;
     	uint8_t time_counter[8]; 
    	for( i = 7; i >= 0 ; i--){
        	time_counter[i] = T & 0xff;
        	T >>= 8;
	}


	uint8_t hmac[SHA1_DIGEST_LENGTH];
	generateHMAC(secret_byte, key_len/2, time_counter, hmac);
	
	int offset = hmac[19] & 0xf;
	int binary = ((hmac[offset] & 0x7f) << 24) | 
			((hmac[offset + 1] & 0xff) << 16) |
			((hmac[offset + 2] & 0xff) << 8)  |
			(hmac[offset + 3] & 0xff); 

	long otp = binary % 1000000;
	int TOTP = atoi(TOTP_string);
	if (otp == TOTP) return 1;
	else return 0;
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
