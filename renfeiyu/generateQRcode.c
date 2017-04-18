#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include "lib/encoding.h"

#define chr2hex(c) ((c - '0' < 10) ? c - '0' : 10 + (c - 'A'))

uint8_t* convert2Hex(char* str){
	int len = strlen(str);
	uint8_t *data = malloc(len);
	memset(data, 0, len);

	int i;
	for(i = 0; i < len/2; i++){
		data[i] = chr2hex(str[i*2]) << 4 | chr2hex(str[i*2 + 1]);
	}
	return data;
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

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	char* encodedIssuer = urlEncode(issuer);
	char* encodedAccountName = urlEncode(accountName);

	uint8_t secretInBase32[20];
	base32_encode(convert2Hex(secret_hex), 10, secretInBase32, 20); 

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	int otpauth_Len = strlen(issuer) + strlen(accountName) + strlen(secretInBase32) + 42;
	char buf[otpauth_Len];

	snprintf(buf, otpauth_Len, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1\n", encodedAccountName, encodedIssuer, secretInBase32);
	displayQRcode(buf);

	snprintf(buf, otpauth_Len, "otpauth://totp/%s?issuer=%s&secret=%s&period=30\n", encodedAccountName, encodedIssuer, secretInBase32);
	displayQRcode(buf);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//displayQRcode("otpauth://testing");

	return (0);
}
