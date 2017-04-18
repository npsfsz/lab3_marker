#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "lib/sha1.h"


//For converting the characters to binary format
static int
hex_to_bin(char c) {
	int diff = 0; 
	if (c >= '0' && c <= '9')
		diff = '0';
	else if (c >= 'A' && c <= 'F')
		diff = 'A' - 10;
	else if (c >= 'a' && c <= 'f')
		diff = 'a' - 10; 
	return (c - diff);
}


//Padding
static void 
pad(char* bin, char* hex) {
	
	int i = 0; 
	char HS[21]; 
        HS[20] = '\0'; 
	//Pad if needed
	int padnum = 0; 
        int len = strlen(hex);
	if(len < 20) {
		padnum = 20 - len; 
		for(i=0; i < len; i++) {
			HS[i] = '0'; //this is hex
		}		
	}
	snprintf(HS + padnum, 21 - padnum, "%s", hex);  //copy it in after padding
	for(i = 0; i < SHA1_BLOCKSIZE; i++) {
                if(i < 10)
		        bin[i] = hex_to_bin(HS[i*2])*16 + hex_to_bin(HS[i*2+1]);  
                else
                        bin[i] = 0x00;
	}
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	long long t = 1; 

	int i = 0;
	uint8_t ipad[SHA1_BLOCKSIZE]; 
	uint8_t opad[SHA1_BLOCKSIZE]; 
	uint8_t k[SHA1_BLOCKSIZE]; 
	pad(k, secret_hex);   
	for(i = 0; i < SHA1_BLOCKSIZE; i++) {
		ipad[i] = 0x36 ^ k[i]; 
		opad[i] = 0x5c ^ k[i];
	}
	uint8_t bc[8];  
	bc[0] = (uint8_t)((t >> 56) & 0xFF);
	bc[1] = (uint8_t)((t >> 48) & 0xFF);
	bc[2] = (uint8_t)((t >> 40) & 0XFF);
	bc[3] = (uint8_t)((t >> 32) & 0XFF);
	bc[4] = (uint8_t)((t >> 24) & 0XFF);
	bc[5] = (uint8_t)((t >> 16) & 0XFF);
	bc[6] = (uint8_t)((t >> 8) & 0XFF);
	bc[7] = (uint8_t)((t & 0XFF));

	SHA1_INFO ctx; 
	uint8_t sha[SHA1_DIGEST_LENGTH]; 
	sha1_init(&ctx); 
	sha1_update(&ctx, ipad, SHA1_BLOCKSIZE); 
	sha1_update(&ctx, bc, 8); 
	sha1_final(&ctx, sha); 
	SHA1_INFO ctx2; 
	uint8_t sha2[SHA1_DIGEST_LENGTH]; 
	sha1_init(&ctx2); 
	sha1_update(&ctx2, opad, SHA1_BLOCKSIZE); 
	sha1_update(&ctx2, sha, SHA1_DIGEST_LENGTH); 
	sha1_final(&ctx2, sha2);

        i = sha2[19]&0xf; 
	if((((sha2[i] & 0x7f) << 24 | (sha2[i + 1] & 0xff) << 16 | (sha2[i + 2] & 0xff) << 8 | (sha2[i + 3] & 0xff)) % 1000000) == atoi(HOTP_string))
		return 1; 
	return 0; 
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	long long t = (long long) (time(0)/30); 

	uint8_t ipad[SHA1_BLOCKSIZE]; 
	uint8_t opad[SHA1_BLOCKSIZE]; 
	uint8_t k[SHA1_BLOCKSIZE];
	pad(k, secret_hex); 
	int i = 0; 
	for(i = 0; i < SHA1_BLOCKSIZE; i++) {
		ipad[i] = 0x36 ^ k[i]; 
		opad[i] = 0x5c ^ k[i]; 
	}
	uint8_t bc[8];  
	bc[0] = (uint8_t)((t >> 56) & 0xFF);
	bc[1] = (uint8_t)((t >> 48) & 0xFF);
	bc[2] = (uint8_t)((t >> 40) & 0XFF);
	bc[3] = (uint8_t)((t >> 32) & 0XFF);
	bc[4] = (uint8_t)((t >> 24) & 0XFF);
	bc[5] = (uint8_t)((t >> 16) & 0XFF);
	bc[6] = (uint8_t)((t >> 8) & 0XFF);
	bc[7] = (uint8_t)((t & 0XFF));

	SHA1_INFO ctx; 
	uint8_t sha[SHA1_DIGEST_LENGTH]; 
	sha1_init(&ctx); 
	sha1_update(&ctx, ipad, SHA1_BLOCKSIZE); 
	sha1_update(&ctx, bc, 8); 
	sha1_final(&ctx, sha); 
	SHA1_INFO ctx2; 
	uint8_t sha2[SHA1_DIGEST_LENGTH]; 
	sha1_init(&ctx2); 
	sha1_update(&ctx2, opad, SHA1_BLOCKSIZE); 
	sha1_update(&ctx2, sha, SHA1_DIGEST_LENGTH); 
	sha1_final(&ctx2, sha2);

        i = sha2[19]&0xf; 
	if((((sha2[i] & 0x7f) << 24 | (sha2[i + 1] & 0xff) << 16 | (sha2[i + 2] & 0xff) << 8 | (sha2[i + 3] & 0xff)) % 1000000) == atoi(TOTP_string))
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
