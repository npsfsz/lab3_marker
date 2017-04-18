#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "lib/sha1.h"


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	SHA1_INFO ctx;
	uint8_t digest1[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH = 20 
	uint8_t digest2[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH = 20 

	char key[10];
	char hex_digit[3] = "00\0";

	int i;
	
	char *pEnd;
	char secret_num_array[10];

	// instead of an ASCII string that contains the secret encoded as
	// hexadecimal characters, we want an array of bytes corresponding
	// to the value of each hexadecimal digit
	for (i=0; i < strlen(secret_hex)/2; i += 1){
		hex_digit[0] = secret_hex[2*i];
		hex_digit[1] = secret_hex[2*i+1];
		secret_num_array[i] = strtol(hex_digit,&pEnd,16);
	}

	// These bytes are equivalent to a 64-bit counter
	// which is set to 1
	// Assume counter is always 1...? Lab handout is unclear
	char counter_byte_array[8];
	bzero(counter_byte_array,8);
	counter_byte_array[7] = 1;

	// this code modified from the hmac RFC (rfc2104)
	// md5 example code, adapted to
	// work with the given sha1 functions

	// RFC 2104 is referenced by RFC 4226

	char k_ipad[65];
	char k_opad[65];

	bzero(k_ipad, 65);
	bzero(k_opad, 65);

	// copies the secret into the ipad and opad arrays
	// then XORs it with the appropriate bit patterns
	bcopy(secret_num_array, k_ipad, 10);
	bcopy(secret_num_array, k_opad, 10);
	
	for (i=0; i<64; i++) {
		k_ipad[i] = k_ipad[i] ^ 0x36;
		k_opad[i] = k_opad[i] ^ 0x5c;
	}

	//creates the inner digest
	//using the ipad and the messsage
	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, 64);
	sha1_update(&ctx, counter_byte_array, 8);
	sha1_final(&ctx, digest1);

	// creates the outer digest using the
	// inner digest and the opad
	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, 64);
	sha1_update(&ctx, digest1, 20);
	sha1_final(&ctx, digest2);	

	//Code below taken from RFC 4226 example code
	int offset = digest2[19] & 0xf ;
	int bin_code = (digest2[offset] & 0x7f) << 24 | (digest2[offset+1] & 0xff) << 16 | (digest2[offset+2] & 0xff) << 8 | (digest2[offset+3] & 0xff);

	// Since we want a 6 digit OTP, we modulo by 1000000 
	int HOTP_int = bin_code % 1000000;
	
	char validation_str[10];
	//need the "06" specifier to deal with OTP codes that have leading zeros
	sprintf(validation_str,"%06d",HOTP_int);

	//printf("%d\n", HOTP_int);
	//printf("%s\n",validation_str);

	//strcmp returns 0 if the strings match
	return strcmp(validation_str,HOTP_string) == 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	SHA1_INFO ctx;
	uint8_t digest1[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH = 20 
	uint8_t digest2[SHA1_DIGEST_LENGTH]; // SHA1_DIGEST_LENGTH = 20 

	char key[10];
	char hex_digit[3] = "00\0";

	int i;
	
	char *pEnd;
	char secret_num_array[10];
	
	// instead of an ASCII string that contains the secret encoded as
	// hexadecimal characters, we want an array of bytes corresponding
	// to the value of each hexadecimal digit

	for (i=0; i < strlen(secret_hex)/2; i += 1){
		hex_digit[0] = secret_hex[2*i];
		hex_digit[1] = secret_hex[2*i+1];
		secret_num_array[i] = strtol(hex_digit,&pEnd,16);
	}

	// From RFC 6238 we can calculate the time value T as:
	// T = (Current Unix time - T0) / X
	// T0 = 0
	// X = 30  (Assume period is always 30? Lab handout is unclear)

	long unsigned int current_time = time(NULL);
	long unsigned int T = current_time / 30;
	char time_byte_array[8];

	// write the value of T into 
	// the 64 bit time_byte_array
	// one byte at a time
	
	for (i=0; i < 8; i+= 1 )
	{
		time_byte_array[7-i] = T & 0xFF;
		T = T >> 8; 
	}
	
	//memcpy(time_byte_array, (char *) &T, 8);

	// this code modified from the hmac RFC (rfc2104)
	// md5 example code, adapted to
	// work with the given sha1 functions

	// RFC 2104 is referenced by RFC 4226

	char k_ipad[65];
	char k_opad[65];

	bzero(k_ipad, 65);
	bzero(k_opad, 65);

	// copies the secret into the ipad and opad arrays
	// then XORs it with the appropriate bit patterns
	bcopy(secret_num_array, k_ipad, 10);
	bcopy(secret_num_array, k_opad, 10);
	
	for (i=0; i<64; i++) {
		k_ipad[i] = k_ipad[i] ^ 0x36;
		k_opad[i] = k_opad[i] ^ 0x5c;
	}

	//creates the inner digest
	//using the ipad and the messsage
	sha1_init(&ctx);
	sha1_update(&ctx, k_ipad, 64);
	sha1_update(&ctx, time_byte_array, 8);
	sha1_final(&ctx, digest1);

	// creates the outer digest using the
	// inner digest and the opad
	sha1_init(&ctx);
	sha1_update(&ctx, k_opad, 64);
	sha1_update(&ctx, digest1, 20);
	sha1_final(&ctx, digest2);	

	//Code below taken from RFC 4226 example code
	int offset = digest2[19] & 0xf ;
	int bin_code = (digest2[offset] & 0x7f) << 24 | (digest2[offset+1] & 0xff) << 16 | (digest2[offset+2] & 0xff) << 8 | (digest2[offset+3] & 0xff);

	// Since we want a 6 digit OTP, we modulo by 1000000 
	int TOTP_int = bin_code % 1000000;
	
	char validation_str[10];
	
	//need the "06" specifier to deal with TOTP codes that have leading zeros
	sprintf(validation_str,"%06d",TOTP_int);

	//strcmp returns 0 if the strings match
	return strcmp(validation_str,TOTP_string) == 0;
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
