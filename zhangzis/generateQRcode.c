#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lib/encoding.h"
#define BUFFER_SIZE 200

int
main(int argc, char * argv[])
{
	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
	char encodedIssuer[BUFFER_SIZE], encodedAccountName[BUFFER_SIZE], secretHexPadded[BUFFER_SIZE], uri[BUFFER_SIZE];
	uint8_t encodedSecret[20], secretHexArray[10];
	int i;

	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	//encrypt credentials
	strcpy(encodedIssuer, urlEncode(issuer));
	strcpy(encodedAccountName, urlEncode(accountName));

	/*char to hex secret*/
	int limit = strlen(secretHexPadded)/2;
	for (i = 0; i<limit; ++i){
		sscanf(secretHexPadded + 2*i, "%02x", &secretHexArray[i]);
	}
	int count = base32_encode(secretHexArray, 10, encodedSecret, 20);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	sprintf(uri, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodedAccountName, encodedIssuer, encodedSecret);
	displayQRcode(uri);
	sprintf(uri, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAccountName, encodedIssuer, encodedSecret);
	displayQRcode(uri);

	//displayQRcode("otpauth://testing");
	return (0);
}
