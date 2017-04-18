#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

#define opad 0x5c
#define ipad 0x36

//HMAC function take in key and message and 
//use opad and ipad to generate hash
void HMAC (uint8_t* bytes, char* m, char* sha)
{
	
	SHA1_INFO ctx1, ctx2;
	uint8_t xor_opad [64];
	uint8_t xor_ipad [64];
	uint8_t temp_buffer [20];
	int i;
	
	sha1_init(&ctx1);
	sha1_init(&ctx2);

	//xor with ipad and opad
	for(i = 0; i != 64; i++)
	{
		xor_opad[i] = bytes[i] ^ opad;
		xor_ipad[i] = bytes[i] ^ ipad;
	}
	
	//generate hash
	sha1_update(&ctx2, xor_ipad, 64);
	sha1_update(&ctx2, m, 8);
	sha1_final(&ctx2, temp_buffer);
	sha1_update(&ctx1, xor_opad, 64);
	sha1_update(&ctx1, temp_buffer, 20);
	sha1_final(&ctx1, sha);
	
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t sha [20];
	uint8_t m[8];	
	int i;
	
	//generate message with counter of 1
	for (i = 0; i != 8 ; i++)
	{
		if(i < 7)
			m[i] = 0;
		else
			m[i] = 1;
	}
	
	//convert secret to bytes
	uint8_t bytes[64];
	for (i = 0; i < 64; i++)
	{
			if(i < 10)
				sscanf(secret_hex + 2*i, "%02x", &bytes[i]);
			else
				bytes[i] = 0;
	}
	
	//compute hash
	HMAC(bytes, m, sha);
	
	//do the calculation of 6-digit value from sha1 hash
	int offset = sha[19] & 0xf;
	int binary_code = (sha[offset] & 0x7f) << 24 | 
	                  (sha[offset+1] & 0xff) << 16 | 
					  (sha[offset+2] & 0xff) << 8 | 
					  (sha[offset+3] & 0xff) ;
					  
	char hotp [7];
	sprintf(hotp, "%d", binary_code%1000000);
	
	//validate
	if(strcmp(hotp, HOTP_string) == 0)
		return 1;
	else
		return 0;
	
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t sha [20];
	uint8_t m[8];
	int i;
	time_t t_sec = time(NULL);
	int time = ((int)t_sec)/30;
	
	//generate message with timeout of 30
	for (i = 0; i != 8 ; i++)
		m[i] = 0;
	
	m[7] = time&0x0ff;
	m[6] = (time>>8)&0x0ff;
	m[5] = (time>>16)&0x0ff;
	m[4] = (time>>24)&0x0ff;
	
	//convert secret to bytes
	uint8_t bytes[64];
	for (i = 0; i < 64; i++)
	{
			if(i < 10)
				sscanf(secret_hex + 2*i, "%02x", &bytes[i]);
			else
				bytes[i] = 0;
	}
	
	//generate hash
	HMAC(bytes, m, sha);
	
	
	//get 6 digit value from hash
	int offset = sha[19] & 0xf;
	int binary_code = (sha[offset] & 0x7f) << 24 | 
	                  (sha[offset+1] & 0xff) << 16 | 
					  (sha[offset+2] & 0xff) << 8 | 
					  (sha[offset+3] & 0xff) ;
					  
	char hotp [7];
	sprintf(hotp, "%d", binary_code%1000000);
	
	if(strcmp(hotp, TOTP_string) == 0)
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

	int slen = strlen(secret_hex);
	int padlen = 20 - slen;
	assert (slen <= 20);

	char adjusted_secret_hex[20];

	int i,j;
	//pad start with zeros if less than 20 bytes provided
	if(padlen > 0 )
	{
		for(i = 0; i != padlen; i++)
			adjusted_secret_hex[i] = '0';

		for( ; i != 20; i++)
				adjusted_secret_hex[i] = secret_hex[i-padlen];
		
	}
	//otherwise just copy the input secret
	else
	{
		for(i = 0; i != 20; i++)
			adjusted_secret_hex[i] = secret_hex[i];
		
	}
	//we want everything to be uppercase so convert everything to uppercase
	for(i = 0; i != slen; i++)
		adjusted_secret_hex[i] = toupper(adjusted_secret_hex[i]);
	
	
	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(adjusted_secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(adjusted_secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
