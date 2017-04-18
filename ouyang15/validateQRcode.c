#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include "lib/sha1.h"

#define blockSize 64
#define IPAD 0x36
#define OPAD 0x5C

void HMAC(uint8_t *key, uint8_t *m, uint8_t * shaouter){

	uint8_t blockKey[blockSize];
	uint8_t o_key_pad[blockSize];
	uint8_t i_key_pad[blockSize];

	int i;
	for(i=0;i<10;i++){
		blockKey[i] = key[i];
	}

	for(i=10;i<blockSize;i++){
		blockKey[i] = 0x00;
	}

	for(i=0;i<blockSize;i++){
		o_key_pad[i] = 0x5c ^ blockKey[i];
		i_key_pad[i] = 0x36 ^ blockKey[i];			
	}

   	SHA1_INFO ctx1;
   	uint8_t shainner[SHA1_DIGEST_LENGTH];
   	sha1_init(&ctx1);
  	sha1_update(&ctx1, i_key_pad, blockSize);
	sha1_update(&ctx1, m,8);
	sha1_final(&ctx1, shainner);

	SHA1_INFO ctx2;
	 //uint8_t shaouter[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx2);
   	sha1_update(&ctx2, o_key_pad, blockSize);
	sha1_update(&ctx2, shainner, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, shaouter);
	
}

int Truncation(uint8_t *hmac_result){
	  int offset   =  hmac_result[19] & 0xf;
      	  int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

        return bin_code;   

}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	char encodedSecret[21] = {0};	
	int i;
	if(strlen(secret_hex)<20)
	{
		int length = strlen(secret_hex);
		int lengthNeeded = 20 - length;	
		for(i=0;i<length;i++)
		{
			encodedSecret[i] = secret_hex[i];
		}

		for(i=length;i<20;i++)
		{
			encodedSecret[i] = '0';
			
		}
	}

	else
	{
		strcpy(encodedSecret, secret_hex);		
	}
	
	uint8_t byteArray[10];
    	uint8_t str_len;
	str_len = strlen(encodedSecret);

   	for (i = 0; i < (str_len / 2); i++) 
    	{
        	sscanf(encodedSecret + 2*i, "%02x", &byteArray[i]);
    	}

	uint8_t counterArray[8] = {0};
    	counterArray[7] = 1;

	uint8_t shaouter[SHA1_DIGEST_LENGTH];

    	HMAC(byteArray, counterArray, shaouter);

    	int sbits = Truncation(shaouter);

    	int modsnum = (int)sbits % (int)(pow(10,6));

    	int HOTP_stringvalue = atoi(HOTP_string);
//printf ("modsnum: %d, HOTP_stringvalue: %d: ", modsnum, HOTP_stringvalue);

    	if (modsnum == HOTP_stringvalue)
    		return 1;
    	else 
    		return 0;

}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	char encodedSecret[21] = {0};	
	int i;
	if(strlen(secret_hex)<20)
	{
		int length = strlen(secret_hex);
		int lengthNeeded = 20 - length;	
		for(i=0;i<length;i++)
		{
			encodedSecret[i] = secret_hex[i];
		}

		for(i=length;i<20;i++)
		{
			encodedSecret[i] = '0';
			
		}
	}

	else
	{
		strcpy(encodedSecret, secret_hex);		
	}
	
	uint8_t byteArray[10];
    	uint8_t str_len;
	str_len = strlen(encodedSecret);

   	for (i = 0; i < (str_len / 2); i++) 
    	{
        	sscanf(encodedSecret + 2*i, "%02x", &byteArray[i]);
    	}

	time_t t = time(NULL);
    	long T = t/30;

   	uint8_t shaouter[SHA1_DIGEST_LENGTH];
   	uint8_t time_bytes[8];
   	for (i = 7; i >= 0; i--) {
   		time_bytes[i] = T;
   		T >>= 8;
   	}

	HMAC(byteArray, time_bytes, shaouter);

    	int sbits = Truncation(shaouter);

    	int modsnum = (int)sbits % (int)(pow(10,6));

    	int TOTP_stringvalue = atoi(TOTP_string);
  //printf ("modsnum: %d, TOTP_stringvalue: %d ", modsnum, TOTP_stringvalue);
   

    	if (modsnum == TOTP_stringvalue)
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

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
