#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include "lib/sha1.h"

int ascii_to_hex(char ascii) {
	char letter = tolower(ascii);
	if(letter >= '0' && letter <= '9') 
	    return letter - '0';
	if(letter >= 'a' && letter <= 'f') 
	    return letter - 'a' + 10; 
}

unsigned int hmac(char * secret_hex, uint8_t* data, int dataLength){

	//HMAC = H[(k xor opad) || H((k xor ipad) || M)];
	//ipad = the byte 0x36 repeated B times
	//opad = the byte 0x5C repeated B times.
	//B the byte-length of blocks = SHA1_BLOCKSIZE
	//L the byte-length of hash outputs (L=20 for SHA-1)
	//The authentication key K can be of any length up to B

	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	SHA1_INFO ctx2;
	uint8_t hmac_result[SHA1_DIGEST_LENGTH];

	if(strlen(secret_hex) > 20) return 0;//Do something else??

	uint8_t secret_len = strlen(secret_hex);
	uint8_t key[10]; //key[secret_len/2]
	
    // Convert string of 20 hex characters to an array of bytes (two hex chars correspond to 1 uint8_t value)
	int i = 0, j = 0;
	for (i = 0; i < (secret_len); i+=2) 
	{
		//sscanf(secret_hex + 2*i, "%02x", &key[i]);
		//printf("bytearray %d: %02x\n", i, bytearray[i]);
		key[j] = 16*ascii_to_hex(secret_hex[i]) + ascii_to_hex(secret_hex[i+1]);
		j++;
	}	

	//compute padding: k xor opad
	uint8_t opad[SHA1_BLOCKSIZE];
	uint8_t ipad[SHA1_BLOCKSIZE];
	uint8_t newKey[SHA1_BLOCKSIZE] = {0};

	for(i  = 0; i<10; i++){
		newKey[i] = key[i];
	}	
	for(i=10; i<SHA1_BLOCKSIZE; i++){
		newKey[i] = 0;
	}

	for(i=0; i<SHA1_BLOCKSIZE; i++){
		ipad[i] = 0x36^newKey[i];
		opad[i] = 0x5C^newKey[i];
	}

	sha1_init(&ctx);
	sha1_update(&ctx, ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, data, dataLength);//message = time or counter(0)
	sha1_final(&ctx, sha);

	sha1_init(&ctx2);
	sha1_update(&ctx2, opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx2, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, hmac_result);
	//returns 20 <data type = 1byte? (uint8) > hash
	//truncate to 6 digits

	int offset = hmac_result[SHA1_DIGEST_LENGTH-1] & 0x0f ;
	int bin_code = (hmac_result[offset] & 0x7f) << 24
			| (hmac_result[offset+1] & 0xff) << 16
			| (hmac_result[offset+2] & 0xff) << 8
			| (hmac_result[offset+3] & 0xff) ;

	unsigned int truncated_hmac = bin_code % (int)pow(10,6);
	return truncated_hmac;
} 


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	unsigned int truncated_hmac;  
	int counter = 1;
    int i;
 
	uint8_t arr[8] = {0};
	arr[7] = 1;
	/*
	for (i = 8; i>0; i--) {
		arr[i-1] = counter;
		counter >>= 8;
	}*/
	
	truncated_hmac = hmac(secret_hex, arr, 8);
	//printf("ivan = %d alby =  %s\n", truncated_hmac, HOTP_string); 
    return (truncated_hmac == atoi(HOTP_string)); 
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	unsigned int truncated_hmac; 
	time_t t = time(NULL);
	int counter;
	int i;
	uint8_t arr[8] = {0};
    counter = ((int)time(NULL))/30; // period = 30
    
	for (i = 8; i>0; i--) {
		arr[i-1] = counter;
		//arr[i-1] = (char)(counter & 0xff);
		counter >>= 8;
	}
	
	truncated_hmac = hmac(secret_hex, arr, 8);
	//printf("ivan = %d alby =  %s\n", truncated_hmac, TOTP_string);
	//compare to TOTP string that we have
    return (truncated_hmac == atoi(TOTP_string)); 
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
