#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>


#include "lib/sha1.h"

#define SHA1_DIGEST_LENGTH 20
#define PADDING_LENGTH 65
#define KEY_SIZE 10 //80 bytes
#define DIGITS 10
#define PERIOD 30

void hmac_SHA1(unsigned char *key, int key_length, uint8_t *counter, int counter_length, uint8_t digest[SHA1_DIGEST_LENGTH])
{
	/*digest is the where the 20 bytes result will go in.*/
	/*counter should always be 8 byte and should be 1*/

	/*HMAC( k, m ) = H( (k XOR k_opad) || H((k ^ k_ipad) || m) )*/
	unsigned char k_ipad[PADDING_LENGTH];
	unsigned char k_opad[PADDING_LENGTH];
	assert(key_length <= PADDING_LENGTH - 1);

	/*storing key in the padding*/
	bzero( k_ipad, sizeof k_ipad);
    bzero( k_opad, sizeof k_opad);
    bcopy( key, k_ipad, key_length);
    bcopy( key, k_opad, key_length);

    /* XOR key with ipad and opad values */
    int i;
    for (i=0; i < PADDING_LENGTH - 1; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /*Perform inner SHA1*/
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, PADDING_LENGTH - 1);
    sha1_update(&ctx, counter, counter_length);
    sha1_final(&ctx, sha);

    /*Perform outer SHA1*/
    SHA1_INFO ctx2;
    sha1_init(&ctx2);
    sha1_update(&ctx2, k_opad, PADDING_LENGTH -1);
    sha1_update(&ctx2, sha, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx2, digest);
    // printf("%s\n", digest);
}

void strtobyte(char * string, int string_length, uint8_t *key, int key_size)
{
	/*convert the argument as string into corresponding bit value. string_length should always be 20*/
	assert(string_length = strlen(string));
	assert(string_length <= key_size * 2);
	int i;
	for( i = 0; i < key_size; i++)
	{
		sscanf(string + 2*i, "%02x", &key[i]);
		// printf("%d\n", key[i]);
	}

}

int truncate(uint8_t string[], int length)
{
	/*string is the result 20 bytes from HMAC function.*/
	assert(length == SHA1_DIGEST_LENGTH);

	/*calculate offset from where the truncate will start.*/
	int offset = string[19] & 0xf;

	/*get the result of truncate*/
	int bin_code = (string[offset]  & 0x7f) << 24
           | (string[offset+1] & 0xff) << 16
           | (string[offset+2] & 0xff) <<  8
           | (string[offset+3] & 0xff) ;

    /*return bin_code mod 10^digits*/
    return bin_code % 1000000;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	/*======================================================*/
	uint8_t digest[SHA1_DIGEST_LENGTH];
	uint8_t secret_b[KEY_SIZE];
	/*I made a mistake here: declared three array of pointers to
	 uint8_t. I should have look at the warning clang gave to me.*/
	uint8_t counter[8] = {0};
	/*======================================================*/
	
	/*build counter*/
	counter[7] = 1;

	/*covert secret for hex to binary*/
	strtobyte(secret_hex, strlen(secret_hex), secret_b, KEY_SIZE);

	/*get HMAC*/
	hmac_SHA1(secret_b, KEY_SIZE, counter, 8, digest);

	/*truncate digest*/
	int HOTP_value = truncate(digest, SHA1_DIGEST_LENGTH);

	if (atoi(HOTP_string) == HOTP_value)
	{
		return 1;
	}else{
		return 0;
	}
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t digest[SHA1_DIGEST_LENGTH];
	uint8_t secret_b[KEY_SIZE];
	uint8_t timeBytes[8] = {0};

	unsigned long long T = time(NULL)/PERIOD;

	/*======================================================*/
	int i = 0;
	uint8_t time_bytes[8];
   	for (i = 7; i >= 0; i--) {
   		time_bytes[i] = T;
   		T >>= 8;
   	}

	// unsigned long long *ptr_T = &T;
	/*covert secret for hex to binary*/
	strtobyte(secret_hex, strlen(secret_hex), secret_b, KEY_SIZE);

	/*get HMAC*/
	// hmac_SHA1(secret_b, KEY_SIZE, (uint8_t *) ptr_T, 8, digest);
	hmac_SHA1(secret_b, KEY_SIZE, time_bytes, 8, digest);

	/*truncate digest*/
	int TOTP_value = truncate(digest, SHA1_DIGEST_LENGTH);

	if (atoi(TOTP_string) == TOTP_value)
	{
		return 1;
	}else{
		return 0;
	}
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
