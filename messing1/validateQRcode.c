#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

#define BLOCK 64

uint8_t* ascii_hex_convert(char* input, size_t length, uint8_t* output);

void getHMAC(uint8_t* secret,  uint8_t* unique, uint8_t* output){

	//declare a key based on the block length
	uint8_t key[BLOCK];

	int i;
	for(i = 0; i < BLOCK ; i++){
		
		if(i < 10){ //10 bytes of key
			key[i] = secret[i];	
		} 
		else { //padding
			key[i] = 0x00;
		}
	}

	uint8_t inner_key[BLOCK];
	uint8_t outer_key[BLOCK];

	for(i = 0; i < BLOCK; i++){
		inner_key[i] = 0x36 ^ key[i]; //mask values from lecture slides, flipped?
		outer_key[i] = 0x5c ^ key[i];
	}

	uint8_t inner_sha[SHA1_DIGEST_LENGTH];

	SHA1_INFO ctx_inner;
	sha1_init(&ctx_inner);

	SHA1_INFO ctx_outter;
	sha1_init(&ctx_outter);

	
	sha1_update(&ctx_inner, inner_key, BLOCK);
	sha1_update(&ctx_inner, unique, 8); //Either counter or time
	sha1_final(&ctx_inner, inner_sha);

	sha1_update(&ctx_outter, outer_key, BLOCK);
	sha1_update(&ctx_outter, inner_sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx_outter, output);

}


int DT(uint8_t* hmac){ //derived from RFC4226 5.4

	int offset = hmac[19] & 0xf;
	int bin_code = (hmac[offset] & 0x7f) << 24
		| (hmac[offset+1] & 0xff) << 16
		| (hmac[offset+2] & 0xff) << 8
		| (hmac[offset+3] & 0xff); 

	return bin_code;
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	char paddedSecret[21];
	int i;
	
	if(strlen(secret_hex) == 20){
		strncpy(paddedSecret, secret_hex, 21);
	}
	else{ //if not long enough
		
		for(i=0; i < strlen(secret_hex); i++){
			paddedSecret[i] = secret_hex[i];
		}
		for(i = strlen(secret_hex); i < 20 ; i++ ){
			paddedSecret[i] = '0';
		}

		//add null char
		paddedSecret[20] = 0;
	}

	//convert to hex
	uint8_t result[10];
	ascii_hex_convert(paddedSecret,20, result);

	//hard coded to value 1
	uint8_t counter[8];
	for(i=0;i<7;i++) counter[i] = 0;

	counter[7] = 1; 

	uint8_t hash[SHA1_DIGEST_LENGTH];

	//determine hmac
	getHMAC(result, counter, hash);

	//trunctation
	int code = DT(hash);

	//get the lower 6 digits
	int modulo = ((int) code) % 1000000;

	//check if the values match
	if(atoi(HOTP_string) == modulo){
		return 1;
	}
	else{
		return 0;
	}

}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	char paddedSecret[21];
	int i;
	
	if(strlen(secret_hex) == 20){
		strncpy(paddedSecret, secret_hex, 21);
	}
	else{ //if not long enough

		for(i=0; i < strlen(secret_hex); i++){
			paddedSecret[i] = secret_hex[i];
		}
		for(i = strlen(secret_hex); i < 20 ; i++ ){
			paddedSecret[i] = '0';
		}

		//add null char
		paddedSecret[20] = 0;
	}

	//convert to hex
	uint8_t result[10];
	ascii_hex_convert(paddedSecret,20, result);

	//get the timer, 30 second period
	time_t timeX = time(NULL);
	long long_time = timeX/30;

	uint8_t timer[8];

	//breakdown the 8 byte long time to 8x1byte array values, most significant bit first in the array
	timer[0] = (uint8_t) ((long_time >> 56) & 0xff);
	timer[1] = (uint8_t) ((long_time >> 48) & 0xff);
	timer[2] = (uint8_t) ((long_time >> 40) & 0xff);
	timer[3] = (uint8_t) ((long_time >> 32) & 0xff);
	timer[4] = (uint8_t) ((long_time >> 24) & 0xff);
	timer[5] = (uint8_t) ((long_time >> 16) & 0xff);
	timer[6] = (uint8_t) ((long_time >> 8) & 0xff);
	timer[7] = (uint8_t) ((long_time) & 0xff);


	uint8_t hash[SHA1_DIGEST_LENGTH];

	//determine hmac
	getHMAC(result, timer, hash);

	//trunctation
	int code = DT(hash);

	//get the lower 6 digits
	int modulo = ((int) code) % 1000000;

	//check if the values match
	if(atoi(TOTP_string) == modulo){
		return 1;
	}
	else{
		return 0;
	}
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

//from part1
uint8_t* ascii_hex_convert(char* input, size_t length, uint8_t* output)
{
    int i=0, j=0, high, low;

    for (; i < length; i+=2,++j) {
        high = input[i] > '9' ? input[i] - 'A' + 10 : input[i] - '0';
        low = input[i+1] > '9' ? input[i+1] - 'A' + 10 : input[i+1] - '0';

        output[j] = (high << 4 ) | low;
    }

    return output;
}