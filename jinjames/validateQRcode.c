#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	
	int i;
	uint8_t secret[10],
		counter[8],
		ip[64],
		op[64],
		key[72];

	//Create counter with padding
	for(i = 0; i < 8; i++){
		counter[i] = 0;		
		if (i == 7)
			counter[i] = 1;
	}

	//Convert secret from ASCII to binary
	for(i = 0; i < 19; i += 2){
		uint8_t v1 = secret_hex[i],
			v2 = secret_hex[i+1];
		if (v1 >= 'A')
			v1 -= 7;
		if (v2 >= 'A')
			v2 -= 7;
		secret[i/2] = ((v1 - 0x30) << 4) + (v2 - 0x30);
	}
	
	//Create inner padded key
	for(i = 0; i < 64; i++){
		ip[i] = 0x36;
		if (i < 10)
			ip[i] = secret[i] ^ 0x36;
	}

	//Hash inner padded key and counter
	sha1_init(&ctx);
	sha1_update(&ctx, ip, 64);
	sha1_update(&ctx, counter, 8);
	sha1_final(&ctx, sha);

	//Create outter padded key
	for(i = 0; i < 64; i++){
		op[i] = 0x5c;
		if (i < 10)
			op[i] = secret[i] ^ 0x5c;
	}

	//Hash outter padded key and previous hash result
	sha1_init(&ctx);
	sha1_update(&ctx, op, 64);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, sha);
	
	//Convert hash result to 6 digit integer value
	int offset = sha[19] & 0xf ;
	int bin_code = (sha[offset] & 0x7f) << 24
		| (sha[offset+1] & 0xff) << 16
		| (sha[offset+2] & 0xff) << 8
		| (sha[offset+3] & 0xff) ;
	int result = bin_code % 1000000;

	//Convert HOTP string to integer value
	int HOTP = 0;
	for (i = 0; i < 6; i++){
		HOTP *= 10;
		HOTP += HOTP_string[i] - '0';
	}

	return result == HOTP;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
	
	int i;
	uint8_t secret[10],
		timer[8],
		ip[64],
		op[64],
		key[72];

	//Get time period
	struct timespec time;
	gettimeofday(&time, NULL);
	time_t now = time.tv_sec;
	int period = now /30;

	//Create counter with padding
	for(i = 0; i < 8; i++){
		timer[i] = 0;		
	}

	//Store the period in 8 bit segments
	timer[7] = period & 0xFF;
	period = period >> 8;
	timer[6] = period & 0xFF;
	period = period >> 8;
	timer[5] = period & 0xFF;
	period = period >> 8;
	timer[4] = period & 0xFF;

	//Convert secret from ASCII to binary
	for(i = 0; i < 19; i += 2){
		uint8_t v1 = secret_hex[i],
			v2 = secret_hex[i+1];
		if (v1 >= 'A')
			v1 -= 7;
		if (v2 >= 'A')
			v2 -= 7;
		secret[i/2] = ((v1 - 0x30) << 4) + (v2 - 0x30);
	}
	
	//Create inner padded key
	for(i = 0; i < 64; i++){
		ip[i] = 0x36;
		if (i < 10)
			ip[i] = secret[i] ^ 0x36;
	}

	//Hash inner padded key and counter
	sha1_init(&ctx);
	sha1_update(&ctx, ip, 64);
	sha1_update(&ctx, timer, 8);
	sha1_final(&ctx, sha);

	//Create outter padded key
	for(i = 0; i < 64; i++){
		op[i] = 0x5c;
		if (i < 10)
			op[i] = secret[i] ^ 0x5c;
	}

	//Hash outter padded key and previous hash result
	sha1_init(&ctx);
	sha1_update(&ctx, op, 64);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, sha);
	
	//Convert hash result to 6 digit integer value
	int offset = sha[19] & 0xf ;
	int bin_code = (sha[offset] & 0x7f) << 24
		| (sha[offset+1] & 0xff) << 16
		| (sha[offset+2] & 0xff) << 8
		| (sha[offset+3] & 0xff) ;
	int result = bin_code % 1000000;

	//Convert HOTP string to integer value
	int TOTP = 0;
	for (i = 0; i < 6; i++){
		TOTP *= 10;
		TOTP += TOTP_string[i] - '0';
	}
	
	printf("%d", result);
	return result == TOTP;
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
