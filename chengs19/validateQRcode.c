#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "lib/sha1.h"

#define IPAD 0x36
#define OPAD 0x5C

void Hmac(uint8_t *key, int key_len, uint8_t *msg, uint8_t *sha_ohash){
	
	uint8_t pad_key[SHA1_BLOCKSIZE];
	uint8_t keyXORipad[SHA1_BLOCKSIZE];
	uint8_t keyXORopad[SHA1_BLOCKSIZE];
	SHA1_INFO ctx1;
	SHA1_INFO ctx2;
	uint8_t sha_ihash[SHA1_DIGEST_LENGTH];
	int i;

	for(i = 0;i < SHA1_BLOCKSIZE; i++){		
		if (i < key_len){
			pad_key[i] = key[i];
		}
		else {
			pad_key[i] = 0x00;
		}
		keyXORipad[i] = pad_key[i] ^ IPAD;
		keyXORopad[i] = pad_key[i] ^ OPAD;		
	}

	sha1_init(&ctx1);
  	sha1_update(&ctx1, keyXORipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx1, msg, 8);
	sha1_final(&ctx1, sha_ihash);
	
	sha1_init(&ctx2);
	sha1_update(&ctx2, keyXORopad, SHA1_BLOCKSIZE);
	sha1_update(&ctx2, sha_ihash, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, sha_ohash);

}



int DynamicTruncation(uint8_t *hmac_result){
	int offset   =  hmac_result[19] & 0xf;
	int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

	return bin_code;   

}

void hexConvert(char *secret_hex, uint8_t *byte_array){
	int i;
	int byte_arrayLen = strlen(secret_hex) / 2;
	for (i = 0; i < (byte_arrayLen); i++) {
        	sscanf(&secret_hex[2*i], "%02x", &byte_array[i]);       
    	}	
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{	
	int  byte_arrayLen = strlen(secret_hex) / 2;
	uint8_t byte_array[byte_arrayLen];
	uint8_t counter_array[8] = {0};
	uint8_t sha_ohash[SHA1_DIGEST_LENGTH];

	hexConvert(secret_hex, byte_array);
    	counter_array[7] = 1;
	Hmac(byte_array, byte_arrayLen, counter_array, sha_ohash);
	
	int trunc_result = DynamicTruncation(sha_ohash);

    	int mod_value = trunc_result % (1000000);

    	int HOTP_value = atoi(HOTP_string);

   	if (mod_value == HOTP_value)
    		return 1;
    	else 
    		return 0;

}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int  byte_arrayLen = strlen(secret_hex) / 2;
	uint8_t byte_array[byte_arrayLen];
	uint8_t time_array[8];
	uint8_t sha_ohash[SHA1_DIGEST_LENGTH];
	time_t T = time(NULL);
    	long t = T/30;
	int i;

	hexConvert(secret_hex, byte_array);
   	for (i = 7; i >= 0; i--) {
   		time_array[i] = t;
   		t >>= 8;
   	}
	Hmac(byte_array, byte_arrayLen, time_array, sha_ohash);
	
	int trunc_result = DynamicTruncation(sha_ohash);

    	int mod_value = trunc_result % (1000000);
	int TOTP_value = atoi(TOTP_string);

   	if (mod_value == TOTP_value)
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
