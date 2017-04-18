#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "lib/sha1.h"


int toHex(char input)
{
    if(input<='z' && input>='a')
    {
        input = 'A' - 'a' + input;
    }

    return (input-'0'<=9) ? input-'0' : input-'A'+10;
}



static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
        SHA1_INFO ctx;
        uint8_t sha[SHA1_DIGEST_LENGTH];
        uint8_t result[SHA1_DIGEST_LENGTH];
        unsigned char k_ipad[SHA1_BLOCKSIZE];
        unsigned char k_opad[SHA1_BLOCKSIZE];

        memset(k_ipad, 0x36, SHA1_BLOCKSIZE);
        memset(k_opad, 0x5c, SHA1_BLOCKSIZE);

        char * key = secret_hex;
        int key_len = 20;
        int i = 0;
	for (i=0; i<key_len; i++)
        {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
        }

        const uint8_t counter[8] = {0,0,0,0,0,0,0,1};
	/*for (i = 8; i--; count >>= 8) {
		counter[i] = count;
        }*/

        sha1_init(&ctx);
        sha1_update(&ctx, k_ipad, SHA1_BLOCKSIZE);
        sha1_update(&ctx, counter, 8); 
        sha1_final(&ctx, sha);
        sha1_init(&ctx);
        sha1_update(&ctx, k_opad, SHA1_BLOCKSIZE);
        sha1_update(&ctx, sha, 20); 
        sha1_final(&ctx, result);

        int offset = result[19] & 0xf ;
	int bin_code = (result[offset] & 0x7f) << 24 | (result[offset+1] & 0xff) << 16 | (result[offset+2] & 0xff) << 8 | (result[offset+3] & 0xff);
        int output = bin_code % 1000000;
	return (output == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
        SHA1_INFO ctx;
        uint8_t sha[SHA1_DIGEST_LENGTH];
        uint8_t result[SHA1_DIGEST_LENGTH];
        unsigned char k_ipad[SHA1_BLOCKSIZE];
        unsigned char k_opad[SHA1_BLOCKSIZE];

        memset(k_ipad, 0x36, SHA1_BLOCKSIZE);
        memset(k_opad, 0x5c, SHA1_BLOCKSIZE);

        char * key = secret_hex;
        int key_len = 20;
        int i = 0;
	for (i=0; i<key_len; i++)
        {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
        }

        unsigned long sec = time(NULL)/30;
        const uint8_t counter[] = {(sec >> 56) & 0xff,(sec >> 48)&0xff,(sec >> 40)&0xff,(sec >> 32)&0xff,(sec >> 24)&0xff,(sec >> 16)&0xff,(sec >> 8)&0xff,sec&0xff};

        sha1_init(&ctx);
        sha1_update(&ctx, k_ipad, SHA1_BLOCKSIZE);
        sha1_update(&ctx, counter, 8); 
        sha1_final(&ctx, sha);
        sha1_init(&ctx);
        sha1_update(&ctx, k_opad, SHA1_BLOCKSIZE);
        sha1_update(&ctx, sha, 20); 
        sha1_final(&ctx, result);

        int offset = result[19] & 0xf ;
	int bin_code = (result[offset] & 0x7f) << 24 | (result[offset+1] & 0xff) << 16 | (result[offset+2] & 0xff) << 8 | (result[offset+3] & 0xff);
        int output = bin_code % 1000000;
	return (output == atoi(TOTP_string));
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


        char paddedStr[20] = "";
        memset(paddedStr,'0',20);
        strncpy(paddedStr,secret_hex,strlen(secret_hex));
        paddedStr[20] = '\0';

        int i,j;
	char strNew[20]="";
        for(i=0,j=0; i<20; i+=2,j++)
        {
                strNew[j] = (char) (16*toHex(paddedStr[i])+toHex(paddedStr[i+1]));
        }

        char * secret_hex_new = strNew;

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		paddedStr,
		HOTP_value,
		validateHOTP(secret_hex_new, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex_new, TOTP_value) ? "valid" : "invalid");

	return(0);
}
