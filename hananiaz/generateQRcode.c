#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#define MAX_LENGTH 128

void shiftBy2(char *input){
	int length = strlen(input);
	int i;
	for(i=0;i<length-2;i++){
		input[i]=input[i+2];
	}
	input[i]='\0';
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
	const char *ACCOUNTNAME;
	const char *ISSUER;
	uint8_t SECRET[MAX_LENGTH];
	uint8_t bytes[10];
	char hotpUri[MAX_LENGTH];
	char totpUri[MAX_LENGTH];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	ACCOUNTNAME=urlEncode(accountName);
	ISSUER=urlEncode(issuer);
	memset(bytes, '\0', 10);
	int i;
	for(i=0;i<10;i++){
		sscanf(secret_hex, "%2x", &bytes[i]);
		shiftBy2(secret_hex);
	}
	base32_encode(bytes, 10, SECRET, MAX_LENGTH);

	sprintf(hotpUri, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", ACCOUNTNAME, ISSUER, SECRET);
	sprintf(totpUri, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", ACCOUNTNAME, ISSUER, SECRET);
	displayQRcode(hotpUri);
	displayQRcode(totpUri);

	return (0);
}
