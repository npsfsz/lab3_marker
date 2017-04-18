#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

#include "lib/sha1.h"


// Helper method to convert hex digit to integer.
unsigned int hexToInt(char in) 
{
	unsigned int out = 0;
	//Check if its a numeric digit
   if(in >= '0' && in <= '9') 
      out =  (in - '0');
  // Check alphabectic lower case digit
   if(in >= 'a' && in <= 'f') 
      out =  (in - 'a') + 10;
  // Check ALphabetic upper case alpha digit.
   if(in >= 'A' && in <= 'F') // upper-case alpha digit
      out =  (in - 'A') + 10;
   return out; 
}

static int compute_otp_Hmac(char * secret_hex, uint8_t * keyVal){

	// secret buffer with padded zero values
	char secret_zeroed[21];
	//Check if zero padding required
	if(strlen(secret_hex)< 20){
		//Compute number of zeroes required
		int diff = 20 - strlen(secret_hex);
		//Copy secret hex first
		int i = 0;
		for(i = 0; i < strlen(secret_hex); i++){
			secret_zeroed[i] = secret_hex[i];
		}
		//pad zeroes
		for(i = strlen(secret_hex); i < 20; i++){
			secret_zeroed[i] = '0';
		}
		//Add null termination
		secret_zeroed[20] = '\0';
		//Update secret hex to zero padded one
		secret_hex = secret_zeroed;
	}


	//Compute Byte array form of secret hex.
	const char * secret_hex_string = secret_hex;
	const char *byteIndex = secret_hex_string;
  	unsigned char secret_hex_byte_array[10];

	// get a byte from secret_hex per 8 bits.
	size_t i = 0;
	for(i = 0; i < 10 ; i++) {
		// get first 4 bits, then shift by 4 and plug in next 4 bits.
		secret_hex_byte_array[i] = (hexToInt(*byteIndex) << 4) | hexToInt(*(byteIndex+1)); 
		byteIndex += 2;
	}

	//HMAC Compute Formula: H (K XOR o_pad, H(K XOR i_pad, message))
	// RFC Document: mentions inner padding (i_pad), outer padding (o_pad)
	// o_pad = 0x5C (B times)
	// i_pad = 0x36 (B times)

	//Setup padding buffers 
	uint8_t i_pad[SHA1_BLOCKSIZE];
	//Zero padding
	memset(i_pad,0,sizeof(i_pad));
	//Copy over secret_byte_array
	memcpy(i_pad, secret_hex_byte_array, 10);

	uint8_t o_pad[SHA1_BLOCKSIZE];
	//Zero padding
	memset(o_pad,0,sizeof(o_pad));
	//Copy over secret_byte_array
	memcpy(o_pad, secret_hex_byte_array, 10);


	int z =0;
	for(z = 0; z < SHA1_BLOCKSIZE; z++){
		i_pad[z] = i_pad[z] ^ 0x36;
		o_pad[z] = o_pad[z] ^ 0x5c;
	}

	SHA1_INFO cntxt;

	sha1_init(&cntxt);
	sha1_update(&cntxt, i_pad, 64);
	sha1_update(&cntxt, keyVal, 8);
	uint8_t mac[SHA1_DIGEST_LENGTH];
	sha1_final(&cntxt, mac);

	sha1_init(&cntxt);
	sha1_update(&cntxt, o_pad,64);
	sha1_update(&cntxt, mac, SHA1_DIGEST_LENGTH);
	sha1_final(&cntxt, mac);

	//From RFC Doc: Computation for digit val 6.
	int offset = mac[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int binary_code = (mac[offset] & 0x7f) << 24 | 
						(mac[offset+1] & 0xff) << 16  | 
						(mac[offset+2] & 0xff) << 8  |
						(mac[offset+3] & 0xff) ;


	int out = binary_code % 1000000;
	return out;

}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t counter[8] = {0,0,0,0,0,0,0,1};
	counter[7] = 1;
	int hotp_hmac = compute_otp_Hmac(secret_hex, counter);
	if(hotp_hmac != atoi(HOTP_string)){
		return (0);
	}
	return (1);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t timer[8] = {0,0,0,0,0,0,0,0};
	//Compute # of time steps.
	time_t numSteps = (time(NULL) - 0)/30;
	int base = 8;
	timer[4] = (numSteps >> (base*3)) & 0xff;
	timer[5] = (numSteps >> base) & 0xff;
	timer[6] = (numSteps >> (base*2)) & 0xff;
	timer[7] = (numSteps) & 0xff;

	int totp_hmac = compute_otp_Hmac(secret_hex, timer);
	if(totp_hmac != atoi(TOTP_string)){
		return (0);
	}
	return (1);
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
