#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

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
        char * encoded_issuer = urlEncode(issuer);
        char * encoded_accountName = urlEncode(issuer);

        uint8_t byte_arr[10];
        int i;
        for (i = 0; i < 10; i+=2){
          sscanf(secret_hex + i, "%02x", &byte_arr[i/2]);
        }

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

        char HOTP[100];
        char TOTP[100];
        char encoded_secret_hex[20];
        int len = base32_encode(byte_arr, 10, encoded_secret_hex, 20);
        snprintf(HOTP, 100, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_accountName, encoded_issuer, encoded_secret_hex);
	snprintf(TOTP, 100, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_accountName, encoded_issuer, encoded_secret_hex);

	displayQRcode(HOTP);
        displayQRcode(TOTP);

	return (0);
}
