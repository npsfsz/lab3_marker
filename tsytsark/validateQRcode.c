#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

// assume key is length 64 bytes and properly zeroed out
// and result is a pointer to a 20 byte array
void hmac_sha1(uint8_t* key, uint8_t* text, uint8_t* result);
uint8_t* dynamic_truncation(uint8_t* input);
uint32_t hotp(uint8_t* key, int key_length, uint8_t* counter, int hotp_length);
uint32_t str_to_num(uint8_t* input, int input_size);
uint8_t* text_to_hex(char* input, int* res_len);
int char_to_hex(char input);


void hmac_sha1(uint8_t* key, uint8_t* text, uint8_t* result){
	uint8_t ipad[64];
	uint8_t opad[64];
	memset(ipad, '\x36', 64);
	memset(opad, '\x5c', 64);
	int i;
	// generate inner and outer keys
	for (i = 0; i < 64; i++){
		ipad[i] = key[i]^ipad[i];
		opad[i] = key[i]^opad[i];
	}

	SHA1_INFO ctx_inner;
	uint8_t sha_inner[SHA1_DIGEST_LENGTH];
	SHA1_INFO ctx_outer;
	uint8_t sha_outer[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx_inner);

	// use the key
	sha1_update(&ctx_inner, ipad, 64);

	// hash the contents
	sha1_update(&ctx_inner, text, 8);

	// get the result of inner sha1 text
	sha1_final(&ctx_inner, sha_inner);


	// start calculating outer hash
	sha1_init(&ctx_outer);

	// use the key
	sha1_update(&ctx_outer, opad, 64);

	// hash the contents
	sha1_update(&ctx_outer, sha_inner, SHA1_DIGEST_LENGTH);

	// get the result of inner sha1 text
	sha1_final(&ctx_outer, sha_outer);

	memcpy(result, sha_outer, 20);
}


uint8_t* dynamic_truncation(uint8_t* input){
	uint32_t offset = str_to_num(&input[19], 1);
	offset = (offset << 28) >> 28;
	input[offset] = (input[offset] << 1) >> 1;
	return &input[offset];
}


uint32_t hotp(uint8_t* key, int key_length, uint8_t* counter, int hotp_length){
	// zero out lower bytes of key, if it is shorter than 64 bytes
	uint8_t normalized_key[64];
	memset(normalized_key, '\x00', 64);
	int i;
	for (i = 0; i < key_length && i < 64; i ++){
		normalized_key[i] = key[i];
	}

  //generate hmac_sha1
	uint8_t hmac_sha1_hash[20];
	hmac_sha1(normalized_key, counter, hmac_sha1_hash);

	uint8_t* truncated_string = dynamic_truncation(hmac_sha1_hash);
	uint32_t result = str_to_num(truncated_string, 4);

	int max_value = 1;
	for (i = 0; i < hotp_length; i++){
		max_value = max_value*10;
	}

	result = result % max_value;
	return result;
}

uint32_t str_to_num(uint8_t* input, int input_size){
	uint32_t result = 0;
	int i = 0;
	while(i < input_size){
		result = result << 8;
		result+=input[i];
		i++;
	}
	return result;
}

uint8_t* text_to_hex(char* input, int* res_len){
	int len = strlen(input);
	// 2 char are 1 byte, in case key length is not byte alligned
	len = len/2 + len%2;
	*res_len = len;
	//allocate space for conversion
	uint8_t* result = malloc(len*sizeof(uint8_t));
	int i;
	for (i = 0; i < len; i++){
		result[i] = char_to_hex(input[i*2]);
		result[i] = result[i] << 4;
		if (char_to_hex(input[i*2+1]) != -1){
			result[i]+=char_to_hex(input[i*2+1]);
		}
	}
	return result;
}

int char_to_hex(char input){
	if(input > 47 && input < 58)
		return (input - 48);
	if(input > 64 && input < 71)
		return (input - 55);
	return -1;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int secret_len;
	char valid_hotp_str[7];
	uint8_t* secret_bin = text_to_hex(secret_hex, &secret_len);

	// the counter value is hardcoded to be 1, since we don't get it as input
	uint8_t counter[8];
	memset (counter, 0, 8);
	counter[7] = 1;

	uint32_t result_hotp =  hotp(secret_bin, secret_len, counter, 6);
	// printf("new hotp: %d\n", result_hotp);
	sprintf(valid_hotp_str, "%06d", result_hotp);
	if(strcmp(valid_hotp_str, HOTP_string)==0)
		return(1);
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int secret_len, i;
	char valid_totp_str[7];
	uint8_t* secret_bin = text_to_hex(secret_hex, &secret_len);

	// get system time
	uint8_t counter[8];
	memset (counter, 0, 8);
	time_t time_sec = time(NULL);
	unsigned time_x = (unsigned) time_sec / 30;
	// since CPU is little endian, and counter is supposed to be big endian,
	// we need to swap the order of bytes
	for(i = 0; i < 4; i++){
		counter[7-i] = (uint8_t) (((time_x >> 8*i)));
	}

	uint32_t result_totp =  hotp(secret_bin, secret_len, counter, 6);
	// printf("new totp: %d\n", result_totp);
	sprintf(valid_totp_str, "%06d", result_totp);
	if(strcmp(valid_totp_str, TOTP_string)==0)
		return(1);
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

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
