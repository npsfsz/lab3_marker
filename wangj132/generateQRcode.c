#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#define NUMOFCHAR 20

// convert from hex to int
int convertHelper(char c) {
    	if(c >= '0' && c <= '9') return c - '0';
    	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    	return 255;
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
	//get length of secret
	int len_secret_hex = strlen(secret_hex);

	assert (len_secret_hex <= NUMOFCHAR);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	const char* encodedIssuer = urlEncode(issuer);
	const char* encodedAccountName = urlEncode(accountName);

	char secret_hex_20[NUMOFCHAR];
	strcpy(secret_hex_20, secret_hex);
	int i;
	//if the length of secret is smaller than 20, add extra 0s
	for (i = len_secret_hex; i<NUMOFCHAR; i++)
		strcat(secret_hex_20, "0");

	// 2 hext = 1 byte
	uint8_t secret_hex_byte[NUMOFCHAR/2];
	for (i = 0; i < NUMOFCHAR; i += 2) {
		secret_hex_byte[i/2] = (16 * convertHelper(secret_hex_20[i])) + (convertHelper(secret_hex_20[i+1]));
	}
	uint8_t encoded_secret_hex[NUMOFCHAR];
	base32_encode(secret_hex_byte, NUMOFCHAR/2, encoded_secret_hex, NUMOFCHAR);
	//get QR string length
	int lenQR = strlen("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n") + strlen(issuer) + strlen(accountName) + strlen(secret_hex_20);

	char hotpQR[lenQR];
	char totpQR[lenQR];
	//generate and display hotp
	sprintf(hotpQR, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodedAccountName, encodedIssuer, encoded_secret_hex);
	displayQRcode(hotpQR);
	//generate and display totp
	sprintf(totpQR, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAccountName, encodedIssuer, encoded_secret_hex);
	displayQRcode(totpQR);

	return (0);
}
