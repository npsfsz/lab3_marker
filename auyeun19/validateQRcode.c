#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "lib/sha1.h"
#include <stdlib.h>
#include <time.h>

#define KEY_LENGTH 64
#define MESSAGE_LENGTH 8
#define COUNTER_VALUE "01"
#define OPAD 0x5c
#define IPAD 0x36


char * calculate_hmac(char * secret_hex, uint8_t message[]){
	//convert the secret hex to binary 
	int len = strlen(secret_hex); 
	uint8_t secret_bin[KEY_LENGTH]; 
	int i; 
	for(i = 0; i < len/2; i++){
		//copy every two string characters to 1 bin value 
		sscanf((2*i)+secret_hex,"%2x",&secret_bin[i]); 
	}
	//pad rest with zero
	for(i = len/2; i < KEY_LENGTH; i++){
		secret_bin[i] = 0x00; 
	}

	/* Generate the ipad and opad XOR vals*/ 
	uint8_t opad = OPAD; 
	uint8_t ipad = IPAD; 
	uint8_t key_xor_opad[KEY_LENGTH]; 
	uint8_t key_xor_ipad[KEY_LENGTH];
	for(i = 0; i < KEY_LENGTH; i ++){
		key_xor_opad[i] = secret_bin[i] ^ opad; 
		key_xor_ipad[i] = secret_bin[i] ^ ipad;
	} 

	/* Generate the HMAC */ 

	//hash the inner key_xor_ipad and counter 
	SHA1_INFO ctx_inner;
	sha1_init(&ctx_inner);
	sha1_update(&ctx_inner, key_xor_ipad, KEY_LENGTH);
	sha1_update(&ctx_inner, message, MESSAGE_LENGTH);
	uint8_t hash_inner[SHA1_DIGEST_LENGTH];
	sha1_final(&ctx_inner, hash_inner);

	//hash the outer key_xor_ipad and counter 
	SHA1_INFO ctx_outer;
	sha1_init(&ctx_outer);
	sha1_update(&ctx_outer, key_xor_opad, KEY_LENGTH);
	sha1_update(&ctx_outer, hash_inner, SHA1_DIGEST_LENGTH);
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	sha1_final(&ctx_outer, hmac);

	// truncate hmac
	int offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int binary = ((hmac[offset] & 0x7f) << 24) |
				 ((hmac[offset + 1] & 0xff) << 16) |
				 ((hmac[offset + 2] & 0xff) << 8) |
				 (hmac[offset + 3] & 0xff);
	int hmac_trunc = binary % 1000000;

	//convert hmac to char * 
	char * hmac_string = (char *)malloc(6*sizeof(char)); 
	sprintf(hmac_string,"%d",hmac_trunc); 

	return hmac_string; 
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	//create the counter array
	uint8_t counter[MESSAGE_LENGTH];
	sscanf(COUNTER_VALUE,"%2x",&counter[MESSAGE_LENGTH-1]);
	int i; 
	for(i = 0; i < MESSAGE_LENGTH-1; i++){
		counter[i] = 0x00; 
	} 
	
	//calculate the hmac
	char * hmac = calculate_hmac(secret_hex,counter); 

	//compare hmac to given HOTP_string
	if(strcmp(hmac,HOTP_string) == 0)
		return 1; 
	else 
		return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	//create the period array
	uint8_t period[MESSAGE_LENGTH];
	int i, shift; 
	time_t now = time(NULL); 
	for(i = MESSAGE_LENGTH-1,shift = 0; i >= 0; i--,shift++){
		period[i] = now/30 >>(shift*8); 
	} 
	
	//calculate the hmac
	char * hmac = calculate_hmac(secret_hex,period); 

	//compare hmac to given HOTP_string
	if(strcmp(hmac,TOTP_string) == 0)
		return 1; 
	else 
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
