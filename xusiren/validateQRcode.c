#include <sys/types.h> // Defines BYTE_ORDER, iff _BSD_SOURCE is defined
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "lib/sha1.h"

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	char k_in[65];
	char k_out[65]; 
	
	bzero(k_in, sizeof(k_in));
	bzero(k_out, sizeof(k_out));
	bcopy(secret_hex, k_in, 10);
	bcopy(secret_hex, k_out, 10);
	
	int i;
	for(i = 0; i < 64; i++) {
		k_in[i] = k_in[i] ^ 0x36;
		k_out[i] = k_out[i] ^ 0x5c;
	}
	
	uint8_t counter[8] = {0, 0, 0, 0, 0, 0, 0, 1};
	
  int result;
  result = sha1_hash(k_in, k_out, counter, HOTP_string);
	
	if(result) {
		return(1);
	} else {
		return(0);
	}
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
  char k_in[65];
	char k_out[65]; 
		
	bzero(k_in, sizeof(k_in));
	bzero(k_out, sizeof(k_out));
	bcopy(secret_hex, k_in, 10);
	bcopy(secret_hex, k_out, 10);
	
	int i;
	for(i = 0; i < 64; i++) {
		k_in[i] = k_in[i] ^ 0x36;
		k_out[i] = k_out[i] ^ 0x5c;
	}
  
  //period 30
  unsigned long long sec;
  sec = (time(NULL))/30;

  //printf("%d", sec&0xff);
  const uint8_t counter[] = {(sec >> 56) & 0xff,(sec >> 48)&0xff,(sec >> 40)&0xff,(sec >> 32)&0xff,(sec >> 24)&0xff,(sec >> 16)&0xff,(sec >> 8)&0xff,sec&0xff};
  
  int result;
  result = sha1_hash(k_in, k_out, counter, TOTP_string);
	
	if(result) {
		return(1);
	} else {
		return(0);
	}
 
}

int sha1_hash(char k_in[65], char k_out[65], uint8_t counter[8], char * TOTP_string) {

	SHA1_INFO ctx;
	
	uint8_t sha[SHA1_DIGEST_LENGTH];
	uint8_t temp[SHA1_DIGEST_LENGTH];

  sha1_init(&ctx);
  sha1_update(&ctx, k_in, 64);
 	sha1_update(&ctx, counter, 8);
	sha1_final(&ctx, temp);
	
	sha1_init(&ctx);
  sha1_update(&ctx, k_out, 64);
 	sha1_update(&ctx, temp, 20);
	sha1_final(&ctx, sha);
 
  int offset = sha[19] & 0xf ;
	int bin_code = (sha[offset] & 0x7f) << 24
	| (sha[offset+1] & 0xff) << 16
	| (sha[offset+2] & 0xff) << 8
	| (sha[offset+3] & 0xff) ;
	
	int a = pow(10,6);
	int out = bin_code % a;
 
  return (out == atoi(TOTP_string));
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
	
	uint8_t myByteArray[10];
	uint8_t myByteArrayLen= strlen(secret_hex);

	int j;
	for (j = 0; j < (myByteArrayLen / 2); j++)
	{
			sscanf(secret_hex + 2*j, "%02x", &myByteArray[j]);
	}

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(myByteArray, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(myByteArray, TOTP_value) ? "valid" : "invalid");

	return(0);
}
