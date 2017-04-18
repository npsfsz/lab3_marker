#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

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

void parseMsg(uint8_t *dest, char* target, int maxMsgLen) {
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
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);
	secret_hex[strlen(secret_hex)] = '\0';
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	int maxMsgLen = 100;
	uint8_t msgParsed[maxMsgLen],encodedMsg[maxMsgLen];
	char hotp[maxMsgLen],totp[maxMsgLen];
	const char *accEncoded, *issuerEncoded;

	accEncoded = urlEncode(accountName);
	issuerEncoded = urlEncode(issuer);

	memset(hotp,0,maxMsgLen);
	memset(totp,0,maxMsgLen);

	parseMsg(msgParsed, secret_hex, maxMsgLen);


	base32_encode(msgParsed, 10, encodedMsg, maxMsgLen);

	snprintf(hotp, maxMsgLen, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accEncoded, issuerEncoded, encodedMsg);
	snprintf(totp, maxMsgLen, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accEncoded, issuerEncoded, encodedMsg);
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}
