#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"

/* Harjot Malhi, 999844824, harjotsingh.malhi@mail.utoronto.ca Atharva
   Atharva Naidu, 999633678, athu.naidu@mail.utoronto.ca */
   
static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	//Set up for padding
	int secret_len = strlen(secret_hex);
	char paddedSecret[20];
	int i;

	//Pad the secret if needed
	if (secret_len<20){
		for (i = 0; i < secret_len; i++)
			paddedSecret[i] = secret_hex[i];
		for (i = secret_len; i < 20; i++)
			paddedSecret[i] = '0';
	}
	else
		strcpy(paddedSecret, secret_hex);
		
	//Convert secret to a byte array
	uint8_t secretByteArray [10];
	 
	for (i = 0; i < 10; i++)
		sscanf(paddedSecret + 2*i, "%02x", &secretByteArray[i]);
	
	//Setup for and then calculate inner and outer hashes
	uint8_t ipad[64], opad[64];

	memcpy(ipad, secretByteArray, 10);
	memcpy(opad, secretByteArray, 10);
	
	for (i = 0; i < 64; i++){
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}
	
	SHA1_INFO ctx;
	SHA1_INFO ctx2;
	uint8_t count[8] = {0};
	count [7] = 1;
	
	//Compute hmac
	uint8_t innerHmac[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, ipad, 64);
	sha1_update(&ctx, count, sizeof(count));
	sha1_final(&ctx, innerHmac);
	
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx2);
	sha1_update(&ctx2, opad, 64);
	sha1_update(&ctx2, innerHmac, sizeof(innerHmac));
	sha1_final(&ctx2, hmac);
	
	//Truncate
	int offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16)| 
				 ((hmac[offset+2] & 0xff) << 8) | (hmac[offset+3] & 0xff) ;
				 
	int binarymod = binary % (int)(pow(10,6));
	
	int HOTPval = atoi(HOTP_string);
	
	if (HOTPval == binarymod)
		return 1;
		
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	//Set up for padding
	int secret_len = strlen(secret_hex);
	char paddedSecret[20];
	int i;

	//Pad the secret if needed
	if (secret_len<20){
		for (i = 0; i < secret_len; i++)
			paddedSecret[i] = secret_hex[i];
		for (i = secret_len; i < 20; i++)
			paddedSecret[i] = '0';
	}
	else
		strcpy(paddedSecret, secret_hex);
		
	//Convert secret to a byte array
	uint8_t secretByteArray [10];
	 
	for (i = 0; i < 10; i++)
		sscanf(paddedSecret + 2*i, "%02x", &secretByteArray[i]);
	
	//Setup for and then calculate inner and outer hashes
	uint8_t ipad[65], opad[65];
	
	memcpy(ipad, secretByteArray, 10);
	memcpy(opad, secretByteArray, 10);
	
	for (i = 0; i < 64; i++){
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}
	
	SHA1_INFO ctx;
	SHA1_INFO ctx2;
	
	long currTime = time(NULL)/30;
	uint8_t timeInBytes[8];
	for (i = 0; i >= 0; i--){
		timeInBytes[i] = currTime;
		currTime >>= 8;
	}
	
	//Compute hmac
	uint8_t innerHmac[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, ipad, 64);
	sha1_update(&ctx, timeInBytes, sizeof(timeInBytes));
	sha1_final(&ctx, innerHmac);
	
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx2);
	sha1_update(&ctx2, opad, 64);
	sha1_update(&ctx2, innerHmac, sizeof(innerHmac));
	sha1_final(&ctx2, hmac);
	
	//Truncate
	int offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0xf;
	int binary = ((hmac[offset]  & 0x7f) << 24) | ((hmac[offset+1]  & 0xff) << 16)| 
				 ((hmac[offset+2]  & 0xff) << 8) | (hmac[offset+3]  & 0xff) ;
				 
	int binarymod = binary % (int)(pow(10,6));
	
	int TOTPval = atoi(TOTP_string);
	
	if (TOTPval == binarymod)
		return 1;
		
	return (0);
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
