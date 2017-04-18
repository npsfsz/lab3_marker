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

	char const * uriEncodedIssuer = urlEncode(issuer);
	char const * uriEncodedAccountName = urlEncode(accountName);

	// handling the input, change string to uint
	uint8_t to_encode[128];
	uint8_t secret[128];
	int secretLength = strlen(secret_hex);

	int i;
	for(i = 0;i < secretLength;i++){
		to_encode[i] = 0;
	}

	for(i = 0 ; i < secretLength;i ++ ){
		uint8_t mynum = secret_hex[i];
		uint8_t newnum = (mynum >= '0' && mynum <= '9')? mynum - '0' : mynum - 'A' + 10;
		if( (i%2) != 0){
			to_encode[i/2] = to_encode[i/2] | newnum;
		}
		else{
			newnum = newnum << 4;
			to_encode[i/2] = to_encode[i/2] | newnum;
		}
	}

	int resultLength = base32_encode(to_encode, secretLength / 2 , secret, 80);
	printf("secret : ");
	for(i = 0 ;i < resultLength; i ++){
		printf("%x ", secret[i]);
	}
	printf("\n");


	char specialUri[128];
	memset(specialUri, '\0', 128);
	strcat(specialUri, "otpauth://hotp/");
	strcat(specialUri, uriEncodedAccountName);
	strcat(specialUri, "?issuer=");
	strcat(specialUri, uriEncodedIssuer);	
	strcat(specialUri, "&secret=");
	strcat(specialUri, secret);
	strcat(specialUri, "&counter=1");
	displayQRcode(specialUri);

	memset(specialUri, '\0', 128);
	strcat(specialUri, "otpauth://totp/");
	strcat(specialUri, uriEncodedAccountName);
	strcat(specialUri, "?issuer=");
	strcat(specialUri, uriEncodedIssuer);
	strcat(specialUri, "&secret=");
	strcat(specialUri, secret);
	strcat(specialUri, "&period=30");
	displayQRcode(specialUri);

	return (0);
}
