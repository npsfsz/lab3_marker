#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>
#include "lib/sha1.h"
#define IPAD 0x36
#define OPAD 0x5C

void char_2_hex(char *input, uint8_t * output){
 	uint8_t  input_len = strlen(input) / 2;
 	int i;
 	for (i = 0; i < input_len; i++)
 		sscanf(input + 2*i, "%02x", &output[i]);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int i;
	char zero_pad = '0';
	uint8_t o_pad_buf[SHA1_BLOCKSIZE], i_pad_buf[SHA1_BLOCKSIZE];
	uint8_t key_buf[SHA1_BLOCKSIZE]; // Will hold the bytes when converted from char to uint8_t
	uint8_t byte_buf[10]; // Will hold the bytes when converted from char to uint8_t
	char_2_hex(secret_hex,byte_buf);
	memset(key_buf, '\x0', SHA1_BLOCKSIZE); // Init with 0's
	memset(i_pad_buf, '\x0', SHA1_BLOCKSIZE); // Init with 0's
	memset(o_pad_buf, '\x0', SHA1_BLOCKSIZE); // Init with 0's
	memcpy(key_buf, byte_buf, 10);
	for(i=0;i<SHA1_BLOCKSIZE;i++){
		i_pad_buf[i] = IPAD ^ key_buf[i];
		o_pad_buf[i] = OPAD ^ key_buf[i];			
	}
	// Inner Hash
	uint8_t counter[8] = {0};
    	counter[7] = 1;
	SHA1_INFO ctx,ctx2;
	uint8_t sha_inner[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, i_pad_buf, 64);
	sha1_update(&ctx, counter, 8);
	sha1_final(&ctx, sha_inner);
	
	// Outer Hash
	uint8_t hmac[SHA1_DIGEST_LENGTH];
    	sha1_init(&ctx2);
    	sha1_update(&ctx2, o_pad_buf, 64);
    	sha1_update(&ctx2, sha_inner, SHA1_DIGEST_LENGTH);
    	sha1_final(&ctx2, hmac);
	
	// Dynamic Truncating
	int offset   =  hmac[19] & 0xf;
      	int bin_code = (hmac[offset]  & 0x7f) << 24
           | (hmac[offset+1] & 0xff) << 16
           | (hmac[offset+2] & 0xff) <<  8
           | (hmac[offset+3] & 0xff) ;
	int HOTP_calc = bin_code % (int)pow(10,6);
	if(HOTP_calc == atoi(HOTP_string)){
		printf("In here\n");
		return 1;
	}
	else
		return 0;
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int i;
	char zero_pad = '0';
	uint8_t o_pad_buf[SHA1_BLOCKSIZE], i_pad_buf[SHA1_BLOCKSIZE];
	uint8_t key_buf[SHA1_BLOCKSIZE]; // Will hold the bytes when converted from char to uint8_t
	uint8_t byte_buf[10]; // Will hold the bytes when converted from char to uint8_t
	char_2_hex(secret_hex,byte_buf);
	memset(key_buf, '\x0', SHA1_BLOCKSIZE); // Init with 0's
	memset(i_pad_buf, '\x0', SHA1_BLOCKSIZE); // Init with 0's
	memset(o_pad_buf, '\x0', SHA1_BLOCKSIZE); // Init with 0's
	memcpy(key_buf, byte_buf, 10);
	for(i=0;i<SHA1_BLOCKSIZE;i++){
		i_pad_buf[i] = IPAD ^ key_buf[i];
		o_pad_buf[i] = OPAD ^ key_buf[i];			
	}
	// Inner Hash
	int t = ((int)time(NULL))/30; // period = 30
	uint8_t timer[8]; 
	for( i = 7; i >= 0 ; i--){
        	timer[i] = t & 0xff;
        	t >>= 8;
   	}
	SHA1_INFO ctx,ctx2;
	uint8_t sha_inner[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, i_pad_buf, 64);
	sha1_update(&ctx, timer, 8);
	sha1_final(&ctx, sha_inner);
	
	// Outer Hash
	uint8_t hmac[SHA1_DIGEST_LENGTH];
    	sha1_init(&ctx2);
    	sha1_update(&ctx2, o_pad_buf, 64);
    	sha1_update(&ctx2, sha_inner, SHA1_DIGEST_LENGTH);
    	sha1_final(&ctx2, hmac);
	
	// Dynamic Truncating
	int offset   =  hmac[19] & 0xf;
      	int bin_code = (hmac[offset]  & 0x7f) << 24
           | (hmac[offset+1] & 0xff) << 16
           | (hmac[offset+2] & 0xff) <<  8
           | (hmac[offset+3] & 0xff) ;
	int TOTP_calc = bin_code % (int)pow(10,6);
	if(TOTP_calc == atoi(TOTP_string)){
		printf("In here\n");
		return 1;
	}
	else
		return 0;
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
	int secret_hex_len = strlen(secret_hex),i;
	char zero_pad = '0';
	char padded_secret[20]; // Max is specified in lab3 doc
	if(secret_hex_len < 20){
		for(i=0;i<20;i++){
			if(i < secret_hex_len)
				padded_secret[i] = secret_hex[i];
                        else
                                padded_secret[i] = zero_pad;
 		}
 	}
	else
		strcpy(padded_secret, secret_hex);
	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(padded_secret, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(padded_secret, TOTP_value) ? "valid" : "invalid");

	return(0);
}
