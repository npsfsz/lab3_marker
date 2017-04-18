#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#define B 64

hex2bin(char h, char* b) {
	b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 0;
	if (h == '1') {
		b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 1;
	}
	else if (h == '2') {
		b[0] = 0; b[1] = 0; b[2] = 1; b[3] = 0;
	}
	else if (h == '3') {
		b[0] = 0; b[1] = 0; b[2] = 1; b[3] = 1;
	}
	else if (h == '4') {
		b[0] = 0; b[1] = 1; b[2] = 0; b[3] = 0;
	}
	else if (h == '5') {
		b[0] = 0; b[1] = 1; b[2] = 0; b[3] = 1;
	}
	else if (h == '6') {
		b[0] = 0; b[1] = 1; b[2] = 1; b[3] = 0;
	}
	else if (h == '7') {
		b[0] = 0; b[1] = 1; b[2] = 1; b[3] = 1;
	}
	else if (h == '8') {
		b[0] = 1; b[1] = 0; b[2] = 0; b[3] = 0;
	}
	else if (h == '9') {
		b[0] = 1; b[1] = 0; b[2] = 0; b[3] = 1;
	}
	else if (h == 'a') {
		b[0] = 1; b[1] = 0; b[2] = 1; b[3] = 0;
	}
	else if (h == 'b') {
		b[0] = 1; b[1] = 0; b[2] = 1; b[3] = 1;
	}
	else if (h == 'c') {
		b[0] = 1; b[1] = 1; b[2] = 0; b[3] = 0;
	}
	else if (h == 'd') {
		b[0] = 1; b[1] = 1; b[2] = 0; b[3] = 1;
	}
	else if (h == 'e') {
		b[0] = 1; b[1] = 1; b[2] = 1; b[3] = 0;
	}
	else if (h == 'f') {
		b[0] = 1; b[1] = 1; b[2] = 1; b[3] = 1;
	}
}

void calcCode(char* secret_hex, uint8_t* m, char* code)
{
	SHA1_INFO ctx1, ctx2;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	uint8_t h[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx1);
	sha1_init(&ctx2);

	uint8_t secret[B];
	char temp[3];
	temp[2] = '\0';
	unsigned i = 0;
	for (i=0;i<20;i+=2){
		temp[0] = secret_hex[i];
		temp[1] = secret_hex[i+1];
		secret[i/2] = (uint8_t) strtol(temp, NULL, 16);
	}
	for (i=10;i<B;i++) {
		secret[i] = 0;
	}

	uint8_t ipad[B];
	uint8_t opad[B];

	for (i=0; i<B; i++) {
		ipad[i] = '\x36';
		opad[i] = '\x5c';
	}

	uint8_t x[B+8];
	int C = B+SHA1_DIGEST_LENGTH;
	uint8_t y[C];
	for (i=0; i<B; i++) {
		x[i] = secret[i] ^ ipad[i];
		y[i] = secret[i] ^ opad[i];
	}
	for (i=B; i<B+8; i++) {
		x[i] = m[i-B];
	}

	sha1_update(&ctx1, x, B+8);
	sha1_final(&ctx1, sha);

	for (i=B; i<C; i++) {
		y[i] = sha[i-B];
	}

	sha1_update(&ctx2, y, C);
	sha1_final(&ctx2, h);

	/*Debug
	uint8_t t[20];
	t[0] = '\x1f';
	t[1] = '\x86';
	t[2] = '\x98';
	t[3] = '\x69';
	t[4] = '\x0e';
	t[5] = '\x02';
	t[6] = '\xca';
	t[7] = '\x16';
	t[8] = '\x61';
	t[9] = '\x85';
	t[10] = '\x50';
	t[11] = '\xef';
	t[12] = '\x7f';
	t[13] = '\x19';
	t[14] = '\xda';
	t[15] = '\x8e';
	t[16] = '\x94';
	t[17] = '\x5b';
	t[18] = '\x55';
	t[19] = '\x5a';
	*/

	int offset = h[19] & 0xf;
	int bin_code =  (h[offset] & 0x7f) << 24 |
					(h[offset+1] & 0xff) << 16 |
					(h[offset+2] & 0xff) << 8 |
					(h[offset+3] & 0xff);

	int code_i = bin_code % (1000000);
	//printf("%d\n", code_i);
	snprintf(code, 7, "%d", code_i);

	/* Debug*/
	/*
	printf("DEBUG\n");
	printf("B: %x\n", B);
	printf("Secret\n");
	for (i=0; i<B; i++) {
		printf("%2x,", secret[i]);
	}
	printf("\n");
	printf("ipad\n");
	for (i=0; i<B; i++) {
		printf("%2x,", ipad[i]);
	}
	printf("\n");
	printf("opad\n");
	for (i=0; i<B; i++) {
		printf("%2x,", opad[i]);
	}
	printf("\n");

	printf("K XOR ipad, M\n");
	for (i=0; i<B+8; i++) {
		printf("%2x,", x[i]);
	}
	printf("\n");
	printf("SHA(key XOR ipad, m)\n");
	for (i=0; i<SHA1_DIGEST_LENGTH; i++) {
		printf("%2x,", sha[i]);
	}
	printf("\n");
	for (i=0; i<C; i++) {
		printf("%x,", y[i]);
	}
	printf("\n");
	printf("SHA final\n");
	for (i=0; i<SHA1_DIGEST_LENGTH; i++) {
		printf("%2x,", h[i]);
	}
	printf("\n");
/*
	*/
	/*
	// ipad and opad
	unsigned int i;
	char ipad[B];
	char opad[B];
	uint8_t ipad_bits[B*4];
	uint8_t opad_bits[B*4];

	for (i=0; i<B; i++) {
		ipad[i] = '\x36';
		hex2bin(ipad[i], &(ipad_bits[i*4]));
		opad[i] = '\x5c';
		hex2bin(opad[i], &(opad_bits[i*4]));
	}

	// pad key to B bytes
	uint8_t key[B*4];
	for (i=0; i<strlen(secret_hex); i++) {
		hex2bin(secret_hex[i], &(key[i*4]));
	}

	for (i=strlen(secret_hex)*4; i<(B*4); i++) {
		key[i] = 0;
	}

	//printf("%s\n", secret_hex);
	for (i=0; i<(B*4); i++) {
		printf("%x", key[i]);
	}
	printf("\n");printf("\n");
	for (i=0; i<(B*4); i++) {
		printf("%x", ipad_bits[i]);
	}
	printf("\n");printf("\n");
	for (i=0; i<(B*4); i++) {
		printf("%x", opad_bits[i]);
	}
	printf("\n");
*/
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	//printf("HOTP\n");
	char code[7];
	uint8_t counter[8];
	counter[0] = 0;
	counter[1] = 0;
	counter[2] = 0;
	counter[3] = 0;
	counter[4] = 0;
	counter[5] = 0;
	counter[6] = 0;
	counter[7] = 1;
	calcCode(secret_hex, counter, code);

	if (strcmp(code, HOTP_string) == 0)
		return 1;
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	//printf("TOTP\n");
	char code[7];
	int ti = time(NULL)/30;
	uint8_t t[8];
	t[7] = ti & 0xff;
	t[6] = (ti >> 8) & 0xff;
	t[5] = (ti >> 16) & 0xff;
	t[4] = (ti >> 24) & 0xff;
	t[3] = 0;//t[3] = (ti >> 32) & 0xff;
	t[2] = 0;//t[2] = (ti >> 40) & 0xff;
	t[1] = 0;//t[1] = (ti >> 48) & 0xff;
	t[0] = 0;//t[0] = (ti >> 56) & 0xff;
	calcCode(secret_hex, t, code);
	if (strcmp(code, TOTP_string) == 0)
		return 1;
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
