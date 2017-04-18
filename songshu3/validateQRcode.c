#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

// ECE568 Lab3 Begin
int HMAC_SHA1(uint8_t *key, uint8_t *counter, uint8_t *hmac_result)
{
    int i;
    uint8_t padded_key[64], ip[64], op[64];
    
    memset(padded_key, 0, 64);
    for(i = 0; i < 10; i++ )
        padded_key[i] = key[i];
    for(i = 0; i < 64; i++ )
    {
        ip[i] = padded_key[i] ^ 0x36;  // 0b00110110
        op[i] = padded_key[i] ^ 0x5c;  // 0b01011100
    }
    
    SHA1_INFO ctx; 
    uint8_t sha_inner[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx); 
    sha1_update(&ctx, ip, 64);
    sha1_update(&ctx, counter, 8);
    sha1_final(&ctx, sha_inner);
    sha1_init(&ctx); 
    sha1_update(&ctx, op, 64);
    sha1_update(&ctx, sha_inner, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, hmac_result);
    
    int offset = hmac_result[19] & 0xf;
    int bin_code = (hmac_result[offset]  & 0x7f) << 24
                 | (hmac_result[offset+1] & 0xff) << 16
                 | (hmac_result[offset+2] & 0xff) <<  8
                 | (hmac_result[offset+3] & 0xff) ;

    return bin_code;
}

int validate(char *secret_hex, uint8_t *counter, char *HOTP_string)
{
    int i;
    uint8_t key[10], hmac_result[SHA1_DIGEST_LENGTH];
    
    for(i = 0; i < 10; i++ )
        sscanf(secret_hex + (2 * i), "%02x", key + i);
    
    int bin_code = HMAC_SHA1(key, counter, hmac_result);
    bin_code = bin_code % 1000000;
    int hotp = atoi(HOTP_string);
    return (hotp == bin_code);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    int i;
    long moving_factor = 1;
    uint8_t text[8];
    for(i = sizeof(text) - 1; i >= 0; i-- )
    {
        text[i] = (char)(moving_factor & 0xff);
        moving_factor >>= 8;
    }
    return validate(secret_hex, text, HOTP_string);
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    int i;
    long moving_factor = ((int)time(NULL))/30;
    uint8_t text[8];
    for(i = sizeof(text) - 1; i >= 0; i-- )
    {
        text[i] = (char)(moving_factor & 0xff);
        moving_factor >>= 8;
    }
    return validate(secret_hex, text, TOTP_string);
	return (0);
}

// ECE568 Lab3 End

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
