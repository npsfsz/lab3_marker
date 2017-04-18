#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "lib/sha1.h"

#define BLOCK_SIZE 64
#define I_PAD 0x36
#define O_PAD 0x5C

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int i,j;
	long count = 1;
	uint8_t *in_pad; 
	uint8_t *out_pad;
	uint8_t count_hex[sizeof(count)];
	uint8_t key[strlen(secret_hex)/2];
	for( i = sizeof(count_hex)-1; i >= 0 ; i--){
		count_hex[i] = (char)(count & 0xff);
		count = count >> 8;
	}
	
	char * pos = secret_hex;
	for (j = 0; j < strlen(secret_hex)/2; j++) {
		sscanf(pos, "%2hhx",&key[j]);
		pos += 2;
	}
	
	in_pad = (uint8_t *)malloc(65*8);
   	memcpy(in_pad, key, strlen(secret_hex)/2);
	out_pad = (uint8_t *)malloc(65*8);
   	memcpy(out_pad, key, strlen(secret_hex)/2);	

	for (i = 0; i < 64; i++) {
        	in_pad[i] ^= 0x36;
        	out_pad[i] ^= 0x5c;
    	}

	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, in_pad, 64);
	sha1_update(&ctx, count_hex, sizeof(count_hex));
	sha1_final(&ctx, sha);

	SHA1_INFO ctx2;
	uint8_t sha1f[SHA1_DIGEST_LENGTH];
    	sha1_init(&ctx2);
    	sha1_update(&ctx2, out_pad, 64);
    	sha1_update(&ctx2, sha, SHA1_DIGEST_LENGTH);
    	sha1_final(&ctx2, sha1f);

	int offset = sha1f[19] & 0xf ;
	int bin_code = (sha1f[offset] & 0x7f) << 24
	| (sha1f[offset+1] & 0xff) << 16
	| (sha1f[offset+2] & 0xff) << 8
	| (sha1f[offset+3] & 0xff) ;

	long hotp = bin_code % 1000000;
	char hotp_str[7];
	sprintf(hotp_str, "%ld", hotp);
	while(strlen(hotp_str) < 6) {
		char temp[7];
		temp[0]='0';
		strcat(temp, hotp_str);
		strcpy(hotp_str, temp);
	}

	
	if (!strcmp(hotp_str, HOTP_string)) {
		return (1);
	}
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int t = (int)time(NULL)/30;

	int i,j;
	uint8_t *in_pad; 
	uint8_t *out_pad;
	uint8_t key[strlen(secret_hex)/2];
	uint8_t t_hex[8]; 
    	for( i = 7; i >= 0 ; i--){
        	t_hex[i] = t & 0xff;
        	t >>= 8;
    	}
	
	char * pos = secret_hex;
	for (j = 0; j < strlen(secret_hex)/2; j++) {
		sscanf(pos, "%2hhx",&key[j]);
		pos += 2;
	}

	in_pad = (uint8_t *)malloc(65*8);
   	memcpy(in_pad, key, strlen(secret_hex)/2);
	out_pad = (uint8_t *)malloc(65*8);
   	memcpy(out_pad, key, strlen(secret_hex)/2);

	for (i = 0; i < 64; i++) {
        	in_pad[i] ^= 0x36;
        	out_pad[i] ^= 0x5c;
    	}

	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, in_pad, 64);
	sha1_update(&ctx, t_hex, sizeof(t_hex));
	sha1_final(&ctx, sha);

	SHA1_INFO ctx2;
	uint8_t sha1f[SHA1_DIGEST_LENGTH];
    	sha1_init(&ctx2);
    	sha1_update(&ctx2, out_pad, 64);
    	sha1_update(&ctx2, sha, SHA1_DIGEST_LENGTH);
    	sha1_final(&ctx2, sha1f);

	int offset = sha1f[19] & 0xf ;
	int bin_code = (sha1f[offset] & 0x7f) << 24
	| (sha1f[offset+1] & 0xff) << 16
	| (sha1f[offset+2] & 0xff) << 8
	| (sha1f[offset+3] & 0xff) ;

	long totp = bin_code % 1000000;
	char totp_str[7];
	sprintf(totp_str, "%ld", totp);
	while(strlen(totp_str) < 6) {
		char temp[7];
		temp[0]='0';
		strcat(temp, totp_str);
		strcpy(totp_str, temp);
	}
	printf("%s\n",totp_str);
	
	if (!strcmp(totp_str, TOTP_string)) {
		return (1);
	}
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
