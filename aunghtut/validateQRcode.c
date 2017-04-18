#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

int validate(char* secret_hex, char* HOTP_string, uint8_t* m){
	//store secret_hex in bytes
	uint8_t secret_b[10];
	int i;
	for(i=0;i<10;i++){
		sscanf(secret_hex + 2*i, "%02x", &secret_b[i]);
	}
	
	//inner and outer padding
	uint8_t ipad[SHA1_BLOCKSIZE];
	uint8_t opad[SHA1_BLOCKSIZE];
	for(i=0;i<10;i++){
		ipad[i] = (secret_b[i] ^ 0x36);
		opad[i] = (secret_b[i] ^ 0x5c);
	}
	assert(i==10);
	while(i<SHA1_BLOCKSIZE){
		ipad[i] = 0^0x36;
		opad[i] = 0^0x5c;
		i++;
	}
	
	//hash function for inner and m
	SHA1_INFO ctx;
	sha1_init(&ctx);
	sha1_update(&ctx,ipad,SHA1_BLOCKSIZE);
	sha1_update(&ctx,m,8);
	uint8_t h1[SHA1_DIGEST_LENGTH];
	sha1_final(&ctx,h1);
	
	//hash function for outer and step 1 hash
	sha1_init(&ctx);
	sha1_update(&ctx,opad,SHA1_BLOCKSIZE);
	sha1_update(&ctx,h1,SHA1_DIGEST_LENGTH);
	uint8_t h2[SHA1_DIGEST_LENGTH];
	sha1_final(&ctx,h2);
	
	//Extraction of a dynamic binary code as desribed in rfc4226 section 5.4
	int offset = h2[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int bin_code = (h2[offset] & 0x7f) << 24
		| (h2[offset+1] & 0xff) << 16
		| (h2[offset+2] & 0xff) << 8
		| (h2[offset+3] & 0xff);
	// We then take this number modulo 1000000 to generate 6 digit
	int oneTimePass = bin_code%1000000;
	char sixdigit[6];
	sprintf(sixdigit,"%d",oneTimePass);
	//pad 0s at front if it has less than 6 digits
	if(strlen(sixdigit) < 6){
		int len = strlen(sixdigit);
		int i;
		char temp[6];
		for(i=0;i<6-len;i++) temp[i] = 0;
		for(i=0;i<len;i++){
			temp[6-len+i] = sixdigit[i];
		}
		strncpy(sixdigit,temp,6);
	}
	return (strncmp(sixdigit,HOTP_string,6) == 0);
	
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t m[8];
	int i;
	for (i=0;i<7;i++) m[i] = 0;
	m[7] = 1;
	
	return validate(secret_hex, HOTP_string, m);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t m[8];
	int timer = ((int)time(NULL))/30;
	int i;
	for(i = 0;i<8;i++){
		m[7-i] = timer;
		timer >>= 8;
	}
	return validate(secret_hex, TOTP_string, m);
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