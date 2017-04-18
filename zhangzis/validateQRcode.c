#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "lib/sha1.h"
#define SECRET_LEN 10
#define COUNTER_LEN 8
#define SHA1_DIGEST_LENGTH 20


void hexToBin (char* string_hex,unsigned char* string_bin){
	int i, j, sum, len = strlen (string_hex);
	char temp1[2], temp2[2];
 	for (i=0;i<len;i=i+2){
 		sum = 0;
 		temp1[0]=string_hex[i];
 		temp2[0]=string_hex[i+1];
 		sum += 16*atoi(temp1) + atoi(temp2);
 		j=i/2;
 		string_bin[j] = sum;
 	}
}

void hmac_sha1(unsigned char* text, int text_len, unsigned char* key, int key_len, uint8_t* digest){
        int i;
        SHA1_INFO ctx;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */

        /*
         * the HMAC_MD5 transform looks like:
         *
         * SHA1(K XOR opad, SHA1(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner SHA1
         */
        sha1_init(&ctx);                   /* init context for 1st
                                              * pass */
        sha1_update(&ctx, k_ipad, 64);      /* start with inner pad */
        sha1_update(&ctx, text, text_len); /* then text of datagram */
        sha1_final(&ctx, digest);          /* finish up 1st pass */
        /*
         * perform outer SHA1
         */
        sha1_init(&ctx);                   /* init context for 2nd
                                          #define SHA1_DIGEST_LENGTH 20    * pass */
        sha1_update(&ctx, k_opad, 64);     /* start with outer pad */
        sha1_update(&ctx, digest, 20);     /* then results of 1st
                                              * hash */
        sha1_final(&ctx, digest);          /* finish up 2nd pass */

}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{

	uint8_t sha[SHA1_DIGEST_LENGTH]; /*SHA1_DIGEST_LENGTH = 10*/
	unsigned char secret_bin[strlen(secret_hex)/2+1];
	unsigned char counter[9];
	int i;
	//set counter to 1
	for (i=0;i<7;i++){
		counter[i] = 0;
	}
	counter[7]=1;

	/*convert string from hex to bin*/
	hexToBin(secret_hex,secret_bin);

	hmac_sha1(counter,COUNTER_LEN,secret_bin,SECRET_LEN,sha);

    /*sha is ready to be truncate*/
    int offset = sha[19]&0xf;
    int bin_code = (sha[offset] & 0x7f)<<24|(sha[offset+1]&0xff)<<16|(sha[offset+2]&0xff)<<8|(sha[offset+3]&0xff);

    int divider_6 = bin_code/1000000;
    int digest_6 = bin_code-divider_6*1000000;

	return digest_6==atoi(HOTP_string)? 1 : 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{

	uint8_t sha[SHA1_DIGEST_LENGTH];
	unsigned char secret_bin[strlen(secret_hex)/2+1];
    int timeinterval_sec = (int)(time(NULL));
    int period = 30;
    int steps = timeinterval_sec/period;
    uint8_t time_counter[COUNTER_LEN];
    int i=7;

    while (i>=0) {
        time_counter[i]=steps&0xff;
        steps = steps>>8;
        i--;
    }

	/*convert string from hex to bin*/
	hexToBin(secret_hex,secret_bin);

	hmac_sha1(time_counter,COUNTER_LEN,secret_bin,SECRET_LEN,sha);

    /*sha is ready to be truncate*/
    int offset = sha[19]&0xf;
    int bin_code = (sha[offset] & 0x7f)<<24|(sha[offset+1]&0xff)<<16|(sha[offset+2]&0xff)<<8|(sha[offset+3]&0xff);

    int divider_6 = bin_code/1000000;
    int digest_6 = bin_code-divider_6*1000000;

	return digest_6==atoi(TOTP_string)? 1 : 0;
}


int
main(int argc, char * argv[])
{

	if ( argc != 4 ) {
		printf("Usage: %s [secretHex0] [HOTP] [TOTP]\n", argv[0]);
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
