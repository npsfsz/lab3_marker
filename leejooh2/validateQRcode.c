#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include "lib/sha1.h"

#define KEY_OPAD 	  0x5C
#define KEY_IPAD      0x36

int generateHMAC(uint8_t * m, int m_len, uint8_t * key, int key_len)
{
	// HMAC = H[(k xor opad) || H((k xor ipad) || M)];
	uint8_t k_ipad[SHA1_BLOCKSIZE] = {0};
	uint8_t k_opad[SHA1_BLOCKSIZE] = {0};
	uint8_t digest1[SHA1_DIGEST_LENGTH];
	uint8_t digest2[SHA1_DIGEST_LENGTH];
	int i;

	for(i = 0; i < key_len; i++)
	{
		k_ipad[i] = key[i];
		k_opad[i] = key[i];
	}

	for(i = 0; i < SHA1_BLOCKSIZE; i++)
	{
		k_ipad[i] ^= KEY_IPAD;
		k_opad[i] ^= KEY_OPAD;
	}

	// perform inner SHA1
	SHA1_INFO context1;
	sha1_init(&context1);
	sha1_update(&context1, k_ipad, SHA1_BLOCKSIZE);
	sha1_update(&context1, m, m_len);
	sha1_final(&context1, digest1);

	// perform outer SHA1
	SHA1_INFO context2;
	sha1_init(&context2);
	sha1_update(&context2, k_opad, SHA1_BLOCKSIZE);
	sha1_update(&context2, digest1, SHA1_DIGEST_LENGTH);
	sha1_final(&context2, digest2);

	// truncate HMAC to 6 characters
	int offset = digest2[19] & 0xF;
	int bin_code = (digest2[offset] & 0x7F) << 24
		| (digest2[offset + 1] & 0xFF) << 16
		| (digest2[offset + 2] & 0xFF) << 8
		| (digest2[offset + 3] & 0xFF);

	return bin_code;
} 

void formatSecret(char * secret_hex, uint8_t * byte_array)
{
	int i = 0;
	char padded_secret[20];
	int padded_zero = strlen(secret_hex);

	if(padded_zero < 20)
	{
		for(i = 0; i < padded_zero; i++)
		{
			padded_secret[i] = secret_hex[i];
		}

		for(i = padded_zero; i < 20; i++)
		{
			padded_secret[i] = '0';
		}
	}
	else
	{
		strcpy(padded_secret, secret_hex);
	}

	//printf("DEBUG = padded secret: %s\n", padded_secret);

	for(i = 0; i < 10; i++)
	{
		sscanf(padded_secret + 2*i, "%02x", &byte_array[i]);
		//printf("DEBUG = byte_secret %d: 0x%d\n", i, byte_array[i]);
	}

	return;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t byte_secret[10];
	formatSecret(secret_hex, byte_secret);

	uint8_t counter[8] = {0};

	counter[7] = 0x01;	// One time ticket-based

	int bin_HOTP = generateHMAC(counter, 8, byte_secret, 10);
	int mod_bin = bin_HOTP % (int)pow(10, 6);

	int HOTP_int = atoi(HOTP_string);

	//printf("DEBUG = HOTP_string: %d\t bin_HOTP: %d\n", HOTP_int, mod_bin);

	if(mod_bin == HOTP_int)
		return (1);

	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t byte_secret[10];
	formatSecret(secret_hex, byte_secret);

	time_t t = time(NULL);
	long period = t/30;

	//printf("DEBUG = period: %ld\nDEBUG = time_key: ", period);

	uint8_t time_key[8];
	int i;
	for(i = 7; i >= 0; i--)
	{
		time_key[i] = period;
		period >>= 8;
	}

	int bin_TOTP = generateHMAC(time_key, 8, byte_secret, 10);
	int mod_bin = bin_TOTP % (int)pow(10, 6);

	int TOTP_int = atoi(TOTP_string);

	//printf("DEBUG = TOTP_string: %d\t bin_TOTP: %d\n", TOTP_int, mod_bin);

	if(mod_bin == TOTP_int)
		return (1);

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
