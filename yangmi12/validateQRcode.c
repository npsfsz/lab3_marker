#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <stdlib.h>
#include <time.h>

#include "lib/sha1.h"

#define OUTER_PAD 0x5c//0x36
#define INNER_PAD 0x36//0x5c

uint8_t counter[]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

uint8_t hexToByte(char hex){
	return	 (hex>='0' && hex<='9') ? hex-'0':
		 (hex>='a' && hex<='f') ? hex-'a'+10:
		 (hex>='A' && hex<='F') ? hex-'A'+10:
		 0xff;
}

uint8_t *strToBytes(char *str){
	int i, byteSize;
	uint8_t *bytes;

	assert(strlen(str)==20);
	byteSize = 10;
	bytes = malloc(byteSize);
	for(i=0; i<byteSize; i++)
		bytes[i]= ( hexToByte(str[2*i])<<4 ) | 
			    hexToByte(str[2*i + 1]);

	return bytes;
}

void hmacSha1(uint8_t hmac[SHA1_DIGEST_LENGTH], uint8_t key[SHA1_DIGEST_LENGTH], uint8_t msg[8]){
	uint8_t ki[SHA1_BLOCKSIZE];
	uint8_t ko[SHA1_BLOCKSIZE];
	uint8_t innerRes[SHA1_DIGEST_LENGTH];
	uint8_t *keyBytes;
	SHA1_INFO ctx;
	int i;

	//Initialize
	memset(ki, INNER_PAD, SHA1_BLOCKSIZE);
	memset(ko, OUTER_PAD, SHA1_BLOCKSIZE);

	//Pad key
	keyBytes = strToBytes(key);//10 chars (i.e. 20 bytes)
	for(i=0; i<SHA1_DIGEST_LENGTH; i++){
		ki[i]=keyBytes[i]^INNER_PAD;
		ko[i]=keyBytes[i]^OUTER_PAD;
	}

	//Inner key
	sha1_init(&ctx);
	sha1_update(&ctx, ki, SHA1_BLOCKSIZE);
	sha1_update(&ctx, msg, 8);
	sha1_final(&ctx, innerRes);

	//Outer key
	sha1_init(&ctx);
	sha1_update(&ctx, ko, SHA1_BLOCKSIZE);
	sha1_update(&ctx, innerRes, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, hmac);
}

int dynamicTruncate(uint8_t hmac[SHA1_DIGEST_LENGTH]){//SHA1_BLOCKSIZE]
	//Find OTP
	int offset = hmac[SHA1_DIGEST_LENGTH-1] & 0xf;
	int binary = ( (hmac[offset] & 0x7f)<<24 )
		|	( (hmac[offset + 1] & 0xff)<<16 )
		|	( (hmac[offset + 2] & 0xff)<<8 )
		|	  (hmac[offset + 3] & 0xff) ;
	int otp = binary % 1000000;
/*
	//Convert to string
	char *result=malloc(7);//6 character val + terminate
	memset(result, 0, 7);
	snprintf(result, 7, "%d", otp);
*/
	return otp;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	int i, hotpFound, isValid;

	//Compute hmac
	memset(hmac, 0, SHA1_DIGEST_LENGTH);
	hmacSha1(hmac, secret_hex, counter);

	//Check truncated value
	hotpFound = dynamicTruncate(hmac);
	//printf("hotp: %d\n", hotpFound);
	isValid = ( hotpFound==atoi(HOTP_string) );

	return isValid;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	uint8_t timeKey[8];
	time_t currTime;
	int i, totopFound, isValid;

	//Find time	
	currTime = time(NULL)/30;
	for(i=7; i>=0; i--){
		timeKey[i]=currTime & 0xff;
		currTime = currTime >> 8;
	}

	//Compute hmac
	memset(hmac, 0, SHA1_DIGEST_LENGTH);
	hmacSha1(hmac, secret_hex, timeKey);

	//Check truncated value
	totopFound = dynamicTruncate(hmac);
	//printf("totop: %d\n", totopFound);
	isValid = (totopFound==atoi(TOTP_string));

	return isValid;
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

