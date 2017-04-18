#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>

#include "lib/sha1.h"

void createString(char* padded_secret_hex, uint8_t* data){
	int i;
	
	// padded_secret_hex is 20 bytes, we want to make it 10 bytes
	// Loop and take 2 bytes and put it into data
	for(i = 0; i < 10 ; i++) {
        sscanf(padded_secret_hex, "%2hhx", &data[i]);
    	padded_secret_hex += 2;
    }

    data[i] = '\0';
}

// Turns the 20 byte HMAC-SHA-1 value into a 31 bit string
int dynamicTruncate(uint8_t* hmacResult) {
	int offset = hmacResult[19] & 0xf;	
	int binaryCode = (hmacResult[offset] & 0x7f) << 24
		| (hmacResult[offset + 1] & 0xff) << 16
		| (hmacResult[offset + 2] & 0xff) << 8
		| (hmacResult[offset + 3] & 0xff);
	return binaryCode % (1000000);
}

int createHMAC(char * secret_hex, char * data, int length){
	char padded_secret_hex[20];
	uint8_t result[64], innerPad[64], outerPad[64], innerSha[SHA1_DIGEST_LENGTH], outerSha[SHA1_DIGEST_LENGTH];
	int i;
	SHA1_INFO ctx1, ctx2;

	memset (padded_secret_hex, 0, 20);

	// Copy the secret into another char array that we can pad if necessary
	strncpy(padded_secret_hex, secret_hex, strlen(secret_hex));

	// Pad the secret with spaces if the length is less than 20
	while (strlen(padded_secret_hex) < 20) {
		padded_secret_hex[strlen(padded_secret_hex)] = ' ';
	}

	padded_secret_hex[20] = '\0';

	// Since base32_encode needs uint, convert char * into uint
	createString(padded_secret_hex, result);

	// The resulting uint are our inner and outer pad values
	strncpy(outerPad, result, 64);
	strncpy(innerPad, result, 64);

	// We need to XOR the pads with their corresponding values
	for(i = 0; i < 64; i++) {
		outerPad[i] ^= 0x5C;
		innerPad[i] ^= 0x36;	
	}

	// Run through the sha encoding process for the inner pad
	sha1_init(&ctx1);
	sha1_update(&ctx1, innerPad, 64);
	if(strlen(data) < length) {
		int8_t dataInBytes[8];
		int value = atoi(data);

		memset (dataInBytes, 0, 8);

		for(i = 0; i < 4; i++) {
			dataInBytes[7 - i] = (value >> (i * 8)) & 0xff;
		}

		sha1_update(&ctx1, dataInBytes, 8);	
	} else {
		sha1_update(&ctx1, data, length);
	}

	sha1_final(&ctx1, innerSha);

	// Run through the sha encoding process for the outer pad
	sha1_init(&ctx2);
	sha1_update(&ctx2, outerPad, 64);

	if(strlen(innerSha) < SHA1_DIGEST_LENGTH) {
		int8_t dataInBytes[8];
		int value = atoi(data);
		
		memset (dataInBytes, 0, 8);

		for(i = 0; i < 4; i++) {
			dataInBytes[7 - i] = (value >> (i * 8)) & 0xff;
		}

		sha1_update(&ctx2, dataInBytes, 8);	
	} else {
		sha1_update(&ctx2, innerSha, SHA1_DIGEST_LENGTH);
	}

	sha1_final(&ctx2, outerSha);

	return dynamicTruncate(outerSha);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	// Generate the HMAC
	int HMAC = createHMAC(secret_hex, "1", 8);
	int HOTPAsInt = atoi(HOTP_string);


	if (HMAC == HOTPAsInt)
		return 1;

	return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// Generate the HMAC by using timestamp
	struct timeval timevalue;
	gettimeofday(&timevalue, NULL);
	unsigned long long timestamp = ((unsigned long long)(timevalue.tv_sec) * 1000) + ((unsigned long long)(timevalue.tv_usec) / 1000);
		
	// Create the timestamp string
	int tStamp = timestamp / 30000;
	char timeString[10];
	snprintf(timeString, 10, "%d", tStamp);  

	int HMAC = createHMAC(secret_hex, timeString, 100);
	int TOTPAsInt = atoi(TOTP_string);

	if (HMAC == TOTPAsInt)
		return 1;

	return 0;
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
