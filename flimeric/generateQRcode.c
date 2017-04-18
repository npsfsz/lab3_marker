#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int char_to_int(char a);

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

    int i;
    char encoded_issuer[256];
    char encoded_accountname[256];
    uint8_t  encoded_secret[256];
    uint8_t data[10];
    strcpy(encoded_issuer, urlEncode(issuer));
    strcpy(encoded_accountname, urlEncode(accountName));


    // base32_code requires the data to be of type uint8_t
    // need to convert the secret hex to this type of array
    
    for (i = 0; i < 20; i += 2)
        data[i >> 1] = char_to_int(secret_hex[i]) * 16 
            + char_to_int(secret_hex[i + 1]);

    i = base32_encode(data, 10, encoded_secret, 256);

    char HOTP[256];
    char TOTP[256];
    snprintf(HOTP, 256, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",
            encoded_accountname, encoded_issuer, encoded_secret);
    snprintf(TOTP, 256, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",
            encoded_accountname, encoded_issuer, encoded_secret);
    displayQRcode(HOTP);
    displayQRcode(TOTP);
    
	return (0);
}

int char_to_int(char a) {
    return (a - '0' <= 9 && a - '0' >= 0) ? a - '0' : 10 + (a - 'A');
}
