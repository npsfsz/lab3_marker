#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

void
convertStringToBinaryArray(char* src, int len, uint8_t* dest) {
	int i;
	for (i = 0; i < len; i++) {
		sscanf(src, "%2hhx", &dest[i]);
		src+=2;
	}
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

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	char  totp[100];
	char  hotp[100];

	char *  encoded_accountName = urlEncode(accountName);
	char *  encoded_issuer = urlEncode(issuer);
	char  encoded_secret_hex[100];

	uint8_t secretKeyBinary[10];
	convertStringToBinaryArray(secret_hex, 10, secretKeyBinary);

	//arguments: source byte array, length (secret is 20 HEX so 10 bytes), destination byte array, buff length of destination
	base32_encode((const uint8_t *)secretKeyBinary, 10, (uint8_t *) encoded_secret_hex, 100);

	snprintf(hotp, 100, "otpauth://hotp/%s?issuer=%s&secret=%s&counter-1", encoded_accountName, encoded_issuer, encoded_secret_hex);
	snprintf(totp, 100, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_accountName, encoded_issuer, encoded_secret_hex);


	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}
