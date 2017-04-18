#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "lib/encoding.h"

int encode(char * secret_hex, uint8_t* key_encode)
{
    int i;
    unsigned int numBytes = strlen(secret_hex)/ 2;
    char* pos = secret_hex;
    uint8_t byteArray [numBytes];
    for (i = 0; i < numBytes; i++) //1 byte = 2 hex
    {
        sscanf(pos, "%2hhX",&byteArray[i]);
        pos = pos + 2;
    }
    
    base32_encode((const uint8_t*)byteArray, numBytes, key_encode, 20);

    return 1;
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
        uint8_t secret_hex_enc[20];
	assert (strlen(secret_hex) <= 20);
        
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
        const char* issuer_enc = urlEncode(issuer);
        const char* accountName_enc = urlEncode(accountName);

        encode(secret_hex, secret_hex_enc);
        printf("done\n");
        int lenhotp = strlen(issuer_enc) + strlen(accountName_enc) + strlen(secret_hex_enc) + strlen("hotpauth://hotp/?issuer=&secret=&counter=1");
        int lentotp = strlen(issuer_enc) + strlen(accountName_enc) + strlen(secret_hex_enc) + strlen("hotpauth://totp/?issuer=&secret=&period=30");
        char* totp = (char*)malloc (lentotp);
        char* hotp = (char*)malloc(lenhotp);
        snprintf(totp, lentotp, "otpauth://hotp/%s?issuer=%s&secret=%s&period=30", accountName_enc, issuer_enc, secret_hex_enc);
        snprintf(hotp, lenhotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName_enc, issuer_enc, secret_hex_enc);
	displayQRcode(totp);
        displayQRcode(hotp);
        
        free(totp);
        free(hotp);

	return (0);
}
