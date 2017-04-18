#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

void convert(){

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

	uint8_t secret_char[10];

	int i;
	for (i = 0; i < 20; i+=2) {
		sscanf(&secret_hex[i], "%2hhx", &secret_char[i/2]);
	}

	/*
	printf("byte_array: ");
	for (i = 0; i < 10; i++) {
		printf("%02x ", secret_char[i]);
	}
	printf("\n");
	*/

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	char secret_base32[17];

	base32_encode((uint8_t *)secret_char, 20, (uint8_t *) secret_base32, 16);


	secret_base32[16] = '\0';

	char uri_hotp[256];
	char uri_totp[256];

	sprintf(uri_hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName, issuer, secret_base32);
	sprintf(uri_totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName, issuer, secret_base32);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode(uri_hotp);
	displayQRcode(uri_totp);

	return (0);
}
