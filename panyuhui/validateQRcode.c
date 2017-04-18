#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

#define SECRET_KEY_SIZE  20
#define SECRET_KEY_SIZE_BASE32 16
#define SECRET_KEY_SIZE_IN_BYTE  10
#define TEXT_SIZE 8
#define NUMBER 1000000
#define TIME_INTERVAL 30

int validate(char *, char *, uint64_t);
void convert_20hex_to_80bit(char *, uint8_t *);
void hmac_sha1(uint8_t *, int, uint8_t *, int, uint8_t *);
int generate_otp(uint8_t *);

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint64_t moving_factor = 1;
	return validate(secret_hex, HOTP_string, moving_factor);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint64_t moving_factor = (uint64_t) (time(NULL) / TIME_INTERVAL);
	return validate(secret_hex, TOTP_string, moving_factor);
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

int
validate(char * secret_hex, char * OTP_string, uint64_t moving_factor){
	uint8_t key[SECRET_KEY_SIZE_IN_BYTE];
	uint8_t text[TEXT_SIZE];
	uint8_t digest[SHA1_DIGEST_LENGTH];
	int i;
	int otp;

	convert_20hex_to_80bit(secret_hex, key);

	for( i = TEXT_SIZE - 1; i >= 0; i--){
		text[i] = (uint8_t) (moving_factor & 0xff);
		moving_factor >>= 8;
	}

	hmac_sha1(text, TEXT_SIZE, key, SECRET_KEY_SIZE_IN_BYTE, digest);

	otp = generate_otp(digest);
		
	int otp_2b_checked = atoi(OTP_string);

	return otp == otp_2b_checked;
}

void 
convert_20hex_to_80bit(char *secret_hex, uint8_t *secret_hex_in_byte){
	char temp_byte_value[3];
	int i;

	// to make strtol safe
	temp_byte_value[3] = '\0';

	for( i = 0 ; i < SECRET_KEY_SIZE_IN_BYTE ; i++ ){
		temp_byte_value[0] = secret_hex[i*2];
		temp_byte_value[1] = secret_hex[i*2+1];
		secret_hex_in_byte[i] = (uint8_t) strtol(temp_byte_value, (char **) NULL, 16);
	}
}

void 
hmac_sha1(uint8_t *text, int text_len, uint8_t *key, int key_len, uint8_t *digest){
	SHA1_INFO ctx;
	//inner padding-key XORd with ipad
	uint8_t k_ipad[SHA1_BLOCKSIZE+1];
	//outer padding-key XORd with opad
	uint8_t k_opad[SHA1_BLOCKSIZE+1];
	int i;

	bzero(k_ipad, SHA1_BLOCKSIZE+1);
	bzero(k_opad, SHA1_BLOCKSIZE+1);
	bcopy(key, k_ipad, key_len);
	bcopy(key, k_opad, key_len);
	
	//XOR the key with ipad and opad values
	for (i = 0; i < SHA1_BLOCKSIZE; i++){
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	// perform inner hash
	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, text, text_len);
	sha1_final(&ctx, digest);

	// perform outer hash
	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, digest, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, digest);
}

// this is actually the truncate function shown in RFC4226
int 
generate_otp(uint8_t *digest){
	int offset = digest[SHA1_DIGEST_LENGTH - 1] & 0xf ;
	int bin_code = (digest[offset] & 0x7f) << 24 \
		| (digest[offset+1] & 0xff) << 16 \
		| (digest[offset+2] & 0xff) << 8 \
		| (digest[offset+3] & 0xff) ;
	return bin_code % NUMBER;
}