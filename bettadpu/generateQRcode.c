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

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

        // Start with Hotp
        char new[1000];
        uint8_t * result = (uint8_t*) malloc(strlen(secret_hex)*sizeof(uint8_t));
        uint8_t encoders[strlen(secret_hex)/2];
        int i = 0;
        
        // Assuming the string is in hex form, then
        // each %2x takes each two hex characters from the 
        // string and places it in encoders[i]. Since encoders
        // is a uint8_t, each element is a byte or 2 hex chars.
        for (i = 0; i < strlen(secret_hex)/2; i++)
            sscanf((i*2)+secret_hex, "%2x", &encoders[i]);
        
        
        int x = base32_encode((encoders), strlen(secret_hex)/2, result, strlen(secret_hex));
        if (x == -1)
        {
            printf("Base Encoding Failed");
            return 0;
        }
        // counter = 1
        sprintf(new, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=%d", urlEncode(accountName), urlEncode(issuer), result, 1);
        displayQRcode(new);

        // Start Totp, period = 30
        sprintf(new, "otpauth://totp/%s?issuer=%s&secret=%s&period=%d", urlEncode(accountName), urlEncode(issuer), result, 30);
        displayQRcode(new);

	return (0);
}
