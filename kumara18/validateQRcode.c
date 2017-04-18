#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#define MAX 1024


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t ipad[64];
	uint8_t opad[64];
	//char * K = secret_hex;
	int secret_hex_len = strlen(secret_hex);
	uint8_t data[secret_hex_len/2];
	uint8_t hmacIPAD[SHA1_DIGEST_LENGTH];
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	int i=0, j=0;
	
	for (i=0; i<10; i++) {
                sscanf(secret_hex + 2*i, "%02x", &data[i]);
        }

        memset(ipad, 0, sizeof(ipad));
        memset(opad, 0, sizeof(opad));
        memcpy(ipad, data, secret_hex_len/2);
        memcpy(opad, data, secret_hex_len/2);

	long counter = 1;
	uint8_t counterConverted[sizeof(long)];
	
	for (i=sizeof(counterConverted)-1;i>= 0;i--) {
		counterConverted[i] = (char)(counter & 0xff);
		counter >>= 8;
	}
	
	//compute HMAC(K,C)=SHA1(K^0x5c5c... || SHA1(K^0x3636... || C))
	//where C is our counter or whatever
	for (i=0;i<64;i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}
	//need to SHA1 ipad
	SHA1_INFO ctx;
	sha1_init(&ctx);
	sha1_update(&ctx,ipad,64);
	sha1_update(&ctx,counterConverted,sizeof(counterConverted));
	sha1_final(&ctx,hmacIPAD);


	//need to SHA1 whole thing
	sha1_init(&ctx);
	sha1_update(&ctx,opad,64);
        sha1_update(&ctx,hmacIPAD,SHA1_DIGEST_LENGTH);
	sha1_final(&ctx,hmac);

	//HOTP Computation for Digit = 6
	int offset = hmac[SHA1_DIGEST_LENGTH -1] & 0xf;
	int bin_code = (hmac[offset] & 0x7f) << 24
		| (hmac[offset+1] & 0xff) << 16
		| (hmac[offset+2] & 0xff) << 8
		| (hmac[offset+3] & 0xff) ;
	
	long D = bin_code % 1000000;
        int HOTP = atoi(HOTP_string);
        if (D == HOTP)
                return 1;
        else
                return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
        uint8_t ipad[64];
        uint8_t opad[64];
        //char * K = secret_hex;
        int secret_hex_len = strlen(secret_hex);
        uint8_t data[secret_hex_len/2];
        uint8_t hmacIPAD[SHA1_DIGEST_LENGTH];
        uint8_t hmac[SHA1_DIGEST_LENGTH];
        int i=0, j=0;

	int t=((int)time(NULL))/30;

	uint8_t timer[8]; 
	for(i=7;i>=0;i--) {
		timer[i] = t&0xff;
		t>>=8;
	}

	for (i=0;i<10;i++) {
		sscanf(secret_hex + 2*i, "%02x", &data[i]);
 	}

        memset(ipad, 0, sizeof(ipad));
        memset(opad, 0, sizeof(opad));
        memcpy(ipad, data, secret_hex_len/2);
        memcpy(opad, data, secret_hex_len/2);

        //compute HMAC(K,C)=SHA1(K^0x5c5c... || SHA1(K^0x3636... || C))
        //where C is our counter or whatever
        for (i=0;i<64;i++) {
		ipad[i] ^= 0x36;
        	opad[i] ^= 0x5c;
	}
        //need to SHA1 ipad
        SHA1_INFO ctx;
        sha1_init(&ctx);
        sha1_update(&ctx,ipad,64);
        sha1_update(&ctx,timer,sizeof(timer));
        sha1_final(&ctx,hmacIPAD);


        //need to SHA1 whole thing
        sha1_init(&ctx);
        sha1_update(&ctx,opad,64);
        sha1_update(&ctx,hmacIPAD,SHA1_DIGEST_LENGTH);
        sha1_final(&ctx,hmac);

        //HOTP Computation for Digit = 6
        int offset = hmac[SHA1_DIGEST_LENGTH -1] & 0xf;
        int bin_code = (hmac[offset] & 0x7f) << 24
                | (hmac[offset+1] & 0xff) << 16
                | (hmac[offset+2] & 0xff) << 8
                | (hmac[offset+3] & 0xff) ;

        int D = bin_code % 1000000; //0 to 10^(Digit-1)
        int TOTP = atoi(TOTP_string);
	if (D == TOTP)
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
