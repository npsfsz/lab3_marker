#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

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

	int slen = strlen(secret_hex);
	int padlen = 20 - slen;
	assert (slen <= 20);

	char adjusted_secret_hex[20];

	int i,j;
	//pad start with zeros if less than 20 bytes provided
	if(padlen > 0 )
	{
		for(i = 0; i != padlen; i++)
			adjusted_secret_hex[i] = '0';

		for( ; i != 20; i++)
				adjusted_secret_hex[i] = secret_hex[i-padlen];
		
	}
	//otherwise just copy the input secret
	else
	{
		for(i = 0; i != 20; i++)
			adjusted_secret_hex[i] = secret_hex[i];
		
	}
	//we want everything to be uppercase so convert everything to uppercase
	for(i = 0; i != slen; i++)
		adjusted_secret_hex[i] = toupper(adjusted_secret_hex[i]);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	//convert secret to byte array
	uint8_t bytes[10];
    	for (i = 0; i < 10; i++) 
        	sscanf(adjusted_secret_hex + 2*i, "%02x", &bytes[i]);       


	uint8_t encoded_secret_hex [20];
	base32_encode(bytes, 10, encoded_secret_hex, 20);

	char hotp [100];
	char totp [100];

	sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", urlEncode(accountName), urlEncode(issuer), encoded_secret_hex);
	sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer), encoded_secret_hex);


	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}