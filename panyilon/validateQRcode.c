#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "lib/sha1.h"

#define HS_LENGTH 20
#define HASH_BLOCK_SIZE 512
static int
DT(uint8_t* HS){
	int offset;	
	int binary;
	
	offset = HS[SHA1_DIGEST_LENGTH-1] & 0xf;
	binary = ((HS[offset] & 0x7f) << 24) | ((HS[offset + 1] & 0xff) << 16) | ((HS[offset + 2] & 0xff) << 8) | (HS[offset + 3] & 0xff); 
	
	return binary;

}

static void 
ComputeHMAC(char * secret_hex, uint8_t *message, uint8_t *sha){

uint8_t opad= 0x5c;
uint8_t ipad=0x36;

int secret_hex_len = strlen(secret_hex);
uint8_t unit8_secret_hex[10];
int i,j;
int integer_secret_hex[secret_hex_len];
char * ref = "0123456789ABCDEF";

int offset = 20 - secret_hex_len;


	// if secret_hex_len is less than 20 bytes, padd its front with 0

	for(i = 0; i < offset; i ++){
			integer_secret_hex[i] = 0;
		}

	// convert secret_hex from str to int array
	for(i = offset; i<20; i++)
	{
		char temp = secret_hex[i-offset];
		integer_secret_hex[i] = -1;
		for( j=0; j<16; j++)
		{
			if(toupper(temp) == ref[j])
			{
			integer_secret_hex[i] = j;
			break;
			}
		}
	}

	for(i = 0; i<20; i++)
	{
		assert(integer_secret_hex[i] >= 0);
	}

	// convert integer_secret_hex to unit8 array
	j = 0;
	for( i=0; i<20; i = i+2)
	{
		if((i+2)%2 == 0)
		{
			unit8_secret_hex[j] = (((integer_secret_hex[i]<<4) & 0x0f0) + (integer_secret_hex[i+1] & 0x0f))&0x0ff;

			j++;
		}
	}

	// Pad binary secret to length
	uint8_t sh_unit8_padded[HASH_BLOCK_SIZE/8];
	for (i = 0; i < (HASH_BLOCK_SIZE/8); i ++){
		sh_unit8_padded[i] = 0;
		if(i < (10)){
			sh_unit8_padded[i] = unit8_secret_hex[i];
		}
	}

	//Compute Hash data
	SHA1_INFO ctx1, ctx2;
	uint8_t sha2[20];
	sha1_init(&ctx1);
	sha1_init(&ctx2);

	uint8_t sh_unit8_padded_opad[HASH_BLOCK_SIZE/8];
	uint8_t sh_unit8_padded_ipad[HASH_BLOCK_SIZE/8];

	for (i = 0; i < (HASH_BLOCK_SIZE/8); i++){
	sh_unit8_padded_ipad[i] = (sh_unit8_padded[i] ^ ipad);
	}
	sha1_update(&ctx2, sh_unit8_padded_ipad, (HASH_BLOCK_SIZE/8));
	sha1_update(&ctx2, message, 8);
	sha1_final(&ctx2, sha2);

	for (i = 0; i < (HASH_BLOCK_SIZE/8); i++){
		sh_unit8_padded_opad[i] = (sh_unit8_padded[i] ^ opad);
	}
	sha1_update(&ctx1, sh_unit8_padded_opad, (HASH_BLOCK_SIZE/8));
	sha1_update(&ctx1, sha2, 20);
	sha1_final(&ctx1, sha);

}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t *sha = (uint8_t *)malloc(sizeof(uint8_t)*(20));
	uint8_t message[8];
	bzero(message,sizeof(message));
	message[7] = 1;
	ComputeHMAC(secret_hex, message, sha);

	int bin_code = DT(sha);
	int hotp_int = bin_code %1000000;

	if(atoi(HOTP_string) == hotp_int)
	{
		return(1);
	}else{
		return (0);
	}
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t *sha = (uint8_t *)malloc(sizeof(uint8_t)*(20));
	time_t sec;
	sec = time(NULL);
	int t = ((int)sec)/30;
	uint8_t message[8];
	bzero(message,sizeof(message));
	message[7] =t&0x0ff;
	message[6] =(t>>8)&0x0ff;
	message[5] =(t>>16)&0x0ff;
	message[4] =(t>>24)&0x0ff;

	ComputeHMAC(secret_hex, message, sha);
	
	int bin_code = DT(sha);
	int totp_int = bin_code %1000000;

	if(atoi(TOTP_string) == totp_int)
	{
		return(1);
	}else{
		return (0);
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
