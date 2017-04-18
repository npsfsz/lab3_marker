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

	char out_1[1024];
	char out_2[1024];
	
	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);
	

	uint8_t myByteArray[10];
    	uint8_t  myByteArrayLen= strlen(secret_hex);
	int i;
    	for (i = 0; i < (myByteArrayLen / 2); i++) 
    	{
		sscanf(secret_hex + 2*i, "%02x", &myByteArray[i]);       
    	}

	uint8_t secret[20];
	int count = 0;
	
	count = base32_encode(myByteArray, 10, secret, 20);
	
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	sprintf(out_1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", urlEncode(accountName), urlEncode(issuer), secret);
  displayQRcode(out_1);

	sprintf(out_2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer),secret);
	displayQRcode(out_2);
	return (0);
}
