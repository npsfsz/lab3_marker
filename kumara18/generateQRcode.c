#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define MAX 1024

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	const char *	issuer = urlEncode(argv[1]);
	const char *	accountName = urlEncode(argv[2]);
	char *	secret_hex = argv[3];
	uint8_t secret_hex_encrypted[MAX];
	int i=0;
	uint8_t secret_uint[10]; //secret_hex will always be 20 Byte hex string, uppercase
	assert (strlen(secret_hex) <= 20);
	for (i=0; i<10; i++) {
        	sscanf(secret_hex + 2*i, "%02x", &secret_uint[i]);       
	}
	base32_encode(secret_uint,10,secret_hex_encrypted,MAX);
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	char hotp[MAX];
	char totp[MAX];
	snprintf(hotp,MAX,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",accountName,issuer,secret_hex_encrypted);
	snprintf(totp,MAX,"otpauth://totp/%s?issuer=%s&secret=%s&period=30",accountName,issuer,secret_hex_encrypted);
	printf("HOTP = %s\n",hotp);	

	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}
