#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

// ECE568 Lab3
#define LENGTH 50

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
        
// ECE568 Lab3 Begin
        char a[LENGTH], b[LENGTH], hotp[300], totp[300];
        uint8_t c[80];
        
        strcpy(a, urlEncode(issuer));
        strcpy(b, urlEncode(accountName));
        base32_encode((const uint8_t *)secret_hex, 20, (uint8_t *)c, 80);
        
        sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", b, a, c);
        sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", b, a, c);
        displayQRcode(hotp);
        displayQRcode(totp);
        
        return 0;
// ECE568 Lab3 End
        
        
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode("otpauth://testing");

	return (0);
}
