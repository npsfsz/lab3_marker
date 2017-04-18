#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "lib/sha1.h"

#define SHA1_DIGEST_LENGTH 20
#define SHA1_BLOCKSIZE 64
#define COUNTER_LENGTH 8

uint8_t hexstr_to_int(char c)
{
    // convert hex string to int
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 255;
}

void hmac(char * secret_hex, uint8_t * counter, uint8_t * hmac_result)
{
	// initialize inner padding, outer padding
        uint8_t k_ipad[SHA1_BLOCKSIZE + 1];
        uint8_t k_opad[SHA1_BLOCKSIZE + 1];
        uint8_t hash_result[SHA1_DIGEST_LENGTH];

	// 1 byte = 8 bits = 2 hex, then key_length = string_length / 2
        int string_length = strlen(secret_hex);
        int key_length = string_length / 2;
        uint8_t key[key_length];
        
	// convert string key to uint8_t array key
        int i;
        int j = 0;

        for (i = 0; i < string_length; i += 2)
        {
            key[j] = hexstr_to_int(secret_hex[i]) * 16 + hexstr_to_int(secret_hex[i + 1]);
            j++;
        }

	// construct inner padding, outer padding
    	memset(k_ipad, 0, sizeof(k_ipad));
        memset(k_opad, 0, sizeof(k_opad));
        memcpy(k_ipad, key, key_length);
        memcpy(k_opad, key, key_length);
    
    	for (i = 0; i < SHA1_BLOCKSIZE; i++) {
        	k_ipad[i] ^= 0x36;
        	k_opad[i] ^= 0x5c;
    	}

	// implement hash step to calculate hmac: hmac = hash(outer_padding + hash(counter + inner_padding))
        SHA1_INFO ctx;

    	sha1_init(&ctx);
    	sha1_update(&ctx, k_ipad, SHA1_BLOCKSIZE);
    	sha1_update(&ctx, counter, COUNTER_LENGTH);
    	sha1_final(&ctx, hash_result);

    	sha1_init(&ctx);
    	sha1_update(&ctx, k_opad, SHA1_BLOCKSIZE);
    	sha1_update(&ctx, hash_result, SHA1_DIGEST_LENGTH);
    	sha1_final(&ctx, hmac_result);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	// initialize counter, hmac value
        uint8_t hmac_result[SHA1_DIGEST_LENGTH];
        uint8_t counter[COUNTER_LENGTH] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

	// calculate hmac value
        hmac(secret_hex, counter, hmac_result);

	// truncate hmac value
        int offset = hmac_result[19] & 0xf ;
        int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

        int hotp_result = bin_code % 1000000;

        return (hotp_result == atoi(HOTP_string));
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// initialize time step, hamc value
        uint8_t hmac_result[SHA1_DIGEST_LENGTH];
        int t = ((int)time(NULL)) / 30;

        int i;
        uint8_t timer[8]; 

        for(i = 7; i >= 0 ; i--)
        {
            timer[i] = t & 0xff;
            t >>= 8;
        }

	// calculate hmac value
        hmac(secret_hex, timer, hmac_result);

	// truncate hmac value
        int offset = hmac_result[19] & 0xf ;
        int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

        int hotp_result = bin_code % 1000000;

        return (hotp_result == atoi(TOTP_string));
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
