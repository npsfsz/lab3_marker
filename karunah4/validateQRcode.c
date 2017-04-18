#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>

#include "lib/sha1.h"

#define OPAD 0x5c
#define IPAD 0x36

void hashSHA1(int8_t* keyPad, int8_t* dataValue, int dataLength, int8_t* retVal);
void convertStringToBinaryArray(char* hexString, int len, int8_t* binaryArr);
void generateHMAC(char *secretKey, int8_t* dataValue, int8_t * hmac);
void convertIntToBinaryArray(int src, int8_t* dest, int destLen);

static int
validateHOTP(char * secretKey, char * HOTP_string)
{
	uint8_t hmac[SHA1_DIGEST_LENGTH], dataValue[8];
	convertIntToBinaryArray(1, dataValue, 8);
    generateHMAC(secretKey, dataValue, hmac);
    int HOTPval = dynamicTruncation(hmac);

    //printf ("HOTP -> Given: %d, Calculated: %d\n", atoi(HOTP_string), HOTPval);
	return (atoi(HOTP_string) == HOTPval);
}

static int
validateTOTP(char * secretKey, char * TOTP_string)
{
	// Calculate timestep
	struct timeval tv;
	gettimeofday(&tv,NULL);
	int timestep = tv.tv_sec/30;

	int8_t hmac[SHA1_DIGEST_LENGTH], dataValue[8];
	convertIntToBinaryArray(timestep, dataValue, 8);
   	generateHMAC(secretKey, dataValue, hmac);
   	int TOTPval = dynamicTruncation(hmac);

	//printf ("TOTP -> Given: %d, Calculated: %d\n", atoi(TOTP_string), TOTPval);
	return (atoi(TOTP_string) == TOTPval);
}

void
convertIntToBinaryArray(int src, int8_t* dest, int destLen) {
	int i;
	for(i = destLen-1; i >= 0 ; i--){
        dest[i] = src & 0xff;
        src >>= 8;
    }
}

void
generateHMAC(char *secretKey, int8_t* dataValue, int8_t * hmac) {
	int8_t iKeyPad[SHA1_BLOCKSIZE], oKeyPad[SHA1_BLOCKSIZE];
	int8_t hashSum1[SHA1_DIGEST_LENGTH], hashSum2[SHA1_DIGEST_LENGTH];

	int8_t secretKeyBinary[SHA1_BLOCKSIZE];
	convertStringToBinaryArray(secretKey, 10, secretKeyBinary);

	int i, j;
	// Pad right of key with zeros
	for (i = 10; i < SHA1_BLOCKSIZE; i++)
		secretKeyBinary[i] = 0;

	// Generate keypads
	for (j = 0; j < SHA1_BLOCKSIZE; j++) {
		iKeyPad[j] = secretKeyBinary[j] ^ IPAD;
		oKeyPad[j] = secretKeyBinary[j] ^ OPAD;
	}

	// Perform SHA-1 Hash
	hashSHA1(iKeyPad, dataValue, sizeof(dataValue), hashSum1);
	hashSHA1(oKeyPad, hashSum1, SHA1_DIGEST_LENGTH, hashSum2);

	memcpy(hmac, hashSum2, SHA1_DIGEST_LENGTH);
}

void
convertStringToBinaryArray(char* src, int len, int8_t* dest) {
	int i;
	for (i = 0; i < len; i++) {
		sscanf(src, "%2hhx", &dest[i]);
		src+=2;
	}
}

void
hashSHA1(int8_t* keyPad, int8_t* dataValue, int dataLength, int8_t* retVal) {
	SHA1_INFO ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, keyPad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, dataValue, dataLength);
	sha1_final(&ctx, retVal);
}

int
dynamicTruncation(int8_t* hmac) {
	int offset = hmac[19] & 0xf;
    int bin_code = (hmac[offset]  & 0x7f) << 24 | (hmac[offset+1] & 0xff) << 16 
    				| (hmac[offset+2] & 0xff) << 8 | (hmac[offset+3] & 0xff);

    return bin_code % 1000000;
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
