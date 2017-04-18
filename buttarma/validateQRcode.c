#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "lib/sha1.h"

#define BUF_SIZE 2048
#define SECRET_HEX_SIZE 20
#define SHA1_BLOCK_SIZE_BYTES 64
#define VAL_SIZE_BYTES 8


#define OPAD_VAL 0x5c
#define IPAD_VAL 0x36

#define CODE_DIGITS 6

int calcHMAC( uint8_t * message, char * key){

	char key_buf[SECRET_HEX_SIZE];
	int i = 0;

	strcpy(key_buf, key);

	for(i = 0; i < SECRET_HEX_SIZE -strlen(key) ; i++ ){
		key_buf[i + strlen(key)] = '0';
	}
	key_buf[i + strlen(key)] = '\0';


	uint8_t secret_buf[SHA1_BLOCK_SIZE_BYTES];
	memset(secret_buf, 0, SHA1_BLOCK_SIZE_BYTES);
	
	for(i = 0; i < 10; i++){
		sscanf(key_buf + 2*i, "%02x", &secret_buf[i]);       

	}


	uint8_t opad[SHA1_BLOCK_SIZE_BYTES], ipad[SHA1_BLOCK_SIZE_BYTES];
	memset(opad, OPAD_VAL, SHA1_BLOCK_SIZE_BYTES);
	memset(ipad, IPAD_VAL, SHA1_BLOCK_SIZE_BYTES);


	for( i = 0; i < SHA1_BLOCK_SIZE_BYTES; i++){
		opad[i] ^= secret_buf[i];
		ipad[i] ^=  secret_buf[i];
	}


	SHA1_INFO ctx;	sha1_init(&ctx);
	uint8_t inner_hash[SHA1_DIGEST_LENGTH];
	uint8_t HMAC[SHA1_DIGEST_LENGTH];

	sha1_update(&ctx, ipad, SHA1_BLOCK_SIZE_BYTES);
	sha1_update(&ctx, message, VAL_SIZE_BYTES);
	// keep calling sha1_update if you have more data to hash...
	sha1_final(&ctx, inner_hash);



	SHA1_INFO ctx2;

	sha1_init(&ctx2);
	sha1_update(&ctx2, opad, SHA1_BLOCK_SIZE_BYTES);
	sha1_update(&ctx2, inner_hash, SHA1_DIGEST_LENGTH);

	sha1_final(&ctx2, HMAC);



	int offset = HMAC[SHA1_DIGEST_LENGTH-1] & 0xf ;
	int bin_code = (HMAC[offset] & 0x7f) << 24| (HMAC[offset+1] & 0xff) << 16	| (HMAC[offset+2] & 0xff) << 8| (HMAC[offset+3] & 0xff) ;

	// printf("%d\n", bin_code %(int) (pow(10,CODE_DIGITS)));
	return bin_code %(int) (pow(10,CODE_DIGITS));

}


void numToBitArray( unsigned int val, uint8_t * array){

	int i = 0;
	for (i=7; i>=0; i--) {
    	array[i] = (uint8_t) val & 0xff;
    	val = val >> 8;
    }
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	unsigned int counter = 1;
	uint8_t counter_bits[VAL_SIZE_BYTES];

	numToBitArray(counter, counter_bits);


	return ((atoi(HOTP_string) == calcHMAC(counter_bits, secret_hex) ) ? 1 : 0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	unsigned int timeval = ((unsigned int)time(NULL))/30; // period = 30
	uint8_t time_bits[VAL_SIZE_BYTES];
  
	numToBitArray(timeval, time_bits);

	return ((atoi(TOTP_string) == calcHMAC(time_bits, secret_hex) ) ? 1 : 0);
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
