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
	char Encode_accountName[128];
	char Encode_issuer[128];
	uint8_t Encode_secret[20];
	int i;
	char outpath1[256];
	char outpath2[256];
	
	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	strcpy(Encode_accountName, urlEncode(accountName));
	strcpy(Encode_issuer, urlEncode(issuer));
	
    	int  byte_arrayLen = strlen(secret_hex) / 2;
	uint8_t byte_array[byte_arrayLen];

    	for (i = 0; i < (byte_arrayLen); i++) {
        	sscanf(&secret_hex[2*i], "%02x", &byte_array[i]);       
    	}
    	
	
	base32_encode(byte_array,byte_arrayLen,Encode_secret,20);

	
	sprintf(outpath1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", Encode_accountName, Encode_issuer, Encode_secret);
	displayQRcode(outpath1);

	sprintf(outpath2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", Encode_accountName, Encode_issuer, Encode_secret);
	displayQRcode(outpath2);

	return (0);
}
