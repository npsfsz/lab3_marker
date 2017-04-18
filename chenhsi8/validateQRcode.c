#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "lib/sha1.h"

int value(char target) {
	if (target >= '0' && target <= '9')
		return target - '0';
	else if (target >= 'a' && target <= 'z')
		return target - 'a' + 10;
	else if (target >= 'A' && target <= 'Z')
		return target - 'A' + 10;
	else
		return 0;
}

int parseMsg(uint8_t *dest, char* target, int maxMsgLen) {
	int count = 0;
	int count1 = 0;
	int targetLen = strlen(target);
	uint8_t upper,lower;
	memset(dest,0,maxMsgLen);
	for (;count < maxMsgLen && count1 < targetLen; count++) {
		upper = value(target[count1++]) << 4;
		lower = value(target[count1++]);
		dest[count] = upper | lower;
	}

	dest[count] = 0;
	return count;
}

int calcOtp(char *secret_hex, uint8_t *info, char *otpStr) {
	int maxMsgLen = 100;
	uint8_t key[maxMsgLen];
	int msgLen = parseMsg(key, secret_hex, maxMsgLen);
	int padSize = 64;
	uint8_t padi[padSize];
	uint8_t pado[padSize];
	memset(padi, 0, padSize);
	memset(pado, 0, padSize);
	memcpy(padi, key, msgLen);
	memcpy(pado, key, msgLen);
	int count = 0;
	for (;count < padSize; count++) {
		padi[count] ^= 0x36;
		pado[count] ^= 0x5c;
	}

	SHA1_INFO ctx;
	uint8_t shai[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, padi, padSize);
	sha1_update(&ctx, info, sizeof(info));
	sha1_final(&ctx, shai);

	uint8_t shao[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, pado, padSize);
	sha1_update(&ctx, shai, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, shao);

	int offset = shao[SHA1_DIGEST_LENGTH - 1] & 0xf;
	long bin = ((shao[offset + 3] & 0xff))
		| ((shao[offset + 2] & 0xff) << 8)
		| ((shao[offset + 1] & 0xff) << 16)
		| ((shao[offset] & 0x7f) << 24);
	long testNum = bin % 1000000;
	long targetNum = atol(otpStr);

	if (testNum == targetNum)
		return 1;
	else
		return 0;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int valSize = 8;
	uint8_t hotpVal[valSize];
	memset(hotpVal, 0, valSize);
	hotpVal[valSize - 1] = 1;
	return calcOtp(secret_hex, hotpVal, HOTP_string);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int valSize = 8;
	uint8_t timeArray[valSize];
	memset(timeArray, 0, valSize);
	long t = time(NULL)/30;
	int count = valSize - 1;
	for (;count >= 0; count--) {
		timeArray[count] = t & 0xff;
		t >>=8;
	}

	return calcOtp(secret_hex,timeArray, TOTP_string);
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
