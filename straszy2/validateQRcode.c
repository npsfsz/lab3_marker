#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"


//this function takes the memory occupied by the secret (10 bytes) and replaces the ASCII value with its corresponding hex value 
//eg. if secret is 123, make binary -> 0001 0010 0011
uint8_t ASCII_to_hex(char c);
uint8_t ASCII_to_hex(char c){
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
}

//this function creates the ipad and opad, creates HMAC, generates a value and compares it to the one given by the user
int create_and_validate(char * secret_hex, uint8_t * data, char * string);
int create_and_validate(char * secret_hex, uint8_t * data, char * string){
	
	//initialize ipad and opad arrays
	uint8_t ipad[64];
	uint8_t opad[64];
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
	
	//need to convert chars (secret) to binary array, size 10 because (20 chars * 4 bits) = (10 * 8 bits)
	uint8_t binary_key[10];
	int i;
	for(i=0;i<20;i+=2){
	   binary_key[i/2]=(ASCII_to_hex(secret_hex[i])*16 + ASCII_to_hex(secret_hex[i+1]));	
	}

	//load ipad and opad with new binary key, get ready to XOR with standard SHA1 values (0x5c for opad, 0x36 for ipad)
	memcpy(ipad, binary_key, 10);
	memcpy(opad, binary_key, 10);

	//XOR key with ipad/opad values
	for(i=0; i<64; i++){
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	//now it is time to create the HMAC. HMAC has the form h = SHA1( key xor opad, SHA1( key xor ipad, message)).
	//first build the inner hash using message and key, then the outer hash using the inner hash and key.
	
	SHA1_INFO ctx;

	uint8_t inner[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, ipad, 64);
	sha1_update(&ctx, data, sizeof(data));
	sha1_final(&ctx, inner);

	uint8_t outer[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, opad, 64);
	sha1_update(&ctx, inner, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, outer); 	
	
	
	//Downsize HMAC to 6 digits, using code described in rfc4226.pdf
	int offset = outer[SHA1_DIGEST_LENGTH - 1] & 0x0f;
	long binary = ((outer[offset] & 0x7f) << 24)
		| ((outer[offset + 1] & 0xff) << 16)
		| ((outer[offset + 2] & 0xff) << 8)
		| ( outer[offset + 3] & 0xff);
	long code = binary % 1000000;
	
	//put code in string to compare with given string
	char code_for_strcmp[7];
	snprintf(code_for_strcmp,7, "%ld",code);
	
	
	//check if generated string matches user provided string, return accordingly
	if(strcmp(string, code_for_strcmp)==0)
		return 1;

	else return 0;
	
	
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int i;
	
	//counter is 1, password can be used once
	long counter = 1;
	int len = 8;
    	uint8_t text[len];

	//convert counter to proper size
   	for( i = len-1; i >= 0 ; i--){
		text[i] = (char)(counter & 0xff);
		counter >>= 8;
	}

    return create_and_validate(secret_hex, text, HOTP_string);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{

	//set up period of timer
	int t = ((int)time(0))/30; 
	
	//convert timer to proper size
    	int i;
    	uint8_t binary_t[8]; 
    	for( i = 7; i >= 0 ; i--){
        	binary_t[i] = t & 0xff;
        	t >>= 8;
    	}

    	return create_and_validate(secret_hex, binary_t, TOTP_string);
}


//didn't make any changes to main
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
