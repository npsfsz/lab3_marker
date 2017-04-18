/*************************


	Lab 3.
	Created by: Peter Tanugraha


**************************/
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include "lib/sha1.h"

//This function excerpt is taken from RFC4226 documentation provided in the course documents
int Truncatetosix(uint8_t *hmac_result){
	  int offset   =  hmac_result[19] & 0xf;
      int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

        return bin_code;   

}

void HMAC(char * formattedSecret, uint8_t *message, uint8_t * shaouter){
	
	//Convert first the secret_hex into bytearray using the same technique as generateQRcode.c
	uint8_t key[10];
	int length = 20; //WE know that the secret will only be length 20.. Hardcoded.
	int i;
   	for (i = 0; i < (length / 2); i++) 
     		   sscanf(formattedSecret + 2*i, "%02x", &key[i]);  

	uint8_t tempKey[64] = {[0 ... 63] = 0x00};
	uint8_t outer_pad[64];
	uint8_t inner_pad[64];

	
	for(i=0;i<10;i++){
		tempKey[i] = key[i];
	}

	for(i=0;i<64;i++){
		outer_pad[i] = 0x5c ^ tempKey[i] ;
		inner_pad[i] = 0x36 ^ tempKey[i] ;
	}

	//First layer of padding
 	SHA1_INFO ctx;
  	uint8_t inner[SHA1_DIGEST_LENGTH];
  	sha1_init(&ctx);
 	sha1_update(&ctx,inner_pad, 64);
	sha1_update(&ctx, message,8);
	sha1_final(&ctx, inner);

	//Create the second layer of padding
	SHA1_INFO ctx2;
	sha1_init(&ctx2);
   	sha1_update(&ctx2, outer_pad, 64);
	sha1_update(&ctx2, inner,SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, shaouter);

	return;

}

//Fill in this function
static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	char formattedSecret[200];


	strcpy(formattedSecret,secret_hex);
	  

	    uint8_t researchArray[8] = {0};
   	 researchArray[7] = 1;


	uint8_t shaouter[SHA1_DIGEST_LENGTH];
	HMAC(formattedSecret,researchArray,shaouter);
	int sbits = Truncatetosix(shaouter);
	int modsnum = (int)sbits % (int)(pow(10,6));
	int InputCheckString = atoi(HOTP_string);


		if (modsnum == InputCheckString)
    		return 1;
    	else 
    		return 0;
}

//Fill in this function
static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int i;
	char formattedSecret[200];


	strcpy(formattedSecret,secret_hex);
	    
	
	//From the research paper RFC provided at portal
	time_t t = time(NULL);
    	long T = t/30;
	
   	uint8_t shaouter[SHA1_DIGEST_LENGTH];
   	uint8_t time_bytes[8];
   	for (i = 7; i >= 0; i--) {
   		time_bytes[i] = T;
   		T >>= 8;
   	}

	HMAC(formattedSecret,time_bytes,shaouter);
	int sbits = Truncatetosix(shaouter);
	int modsnum = (int)sbits % (int)(pow(10,6));
	int InputCheckString = atoi(TOTP_string);

	

	if (modsnum == InputCheckString)
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
