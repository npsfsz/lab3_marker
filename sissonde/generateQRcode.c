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

	//Objects
	char URI_HOTP[120] = "otpauth://hotp/";
	char URI_TOTP[120] = "otpauth://totp/";
	char url_issuer[30];
	char url_accountName[30];
	char url_secret[17];
	char * stringPtr;
	int iter;
	uint8_t secret[10];

	//Format the input
	stringPtr = urlEncode(issuer);
	strncpy(url_issuer,stringPtr,sizeof(url_issuer));

	stringPtr = urlEncode(accountName);
	strncpy(url_accountName,stringPtr,sizeof(url_accountName));

	//Hex to Binary using uint8_t format, 2 hexes per uint8_t
	for(iter=0;iter<20;iter=iter+2){
		uint8_t ascii = (uint8_t)secret_hex[iter];
		if(ascii>=48&&ascii<=57) 
			ascii = ascii-48;
		if(ascii>=65&&ascii<=70)
			ascii = ascii-55;
		
		uint8_t ascii2 = (uint8_t)secret_hex[iter+1];
		if(ascii2>=48&&ascii2<=57)
			ascii2 = ascii2-48;
		if(ascii2>=65&&ascii2<=70)
			ascii2 = ascii2-55;
		
		secret[(uint8_t)iter/2] = ascii*16+ascii2;
	}
	
	//Encode to BASE32
	if(base32_encode(secret, 10, url_secret, 16)==-1){
		printf("Base32 Encoding Error\n");
		return -1;
	}
	url_secret[16] = '\0';

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	//Concatenate to URI_HOTP and URI_TOTP
	strcat(URI_HOTP, url_accountName);
	strcat(URI_HOTP, "?issuer=");
	strcat(URI_HOTP, url_issuer);
	strcat(URI_HOTP, "&secret=");
	strcat(URI_HOTP, url_secret);
	strcat(URI_HOTP, "&counter=1");

	strcat(URI_TOTP, url_accountName);
	strcat(URI_TOTP, "?issuer=");
	strcat(URI_TOTP, url_issuer);
	strcat(URI_TOTP, "&secret=");
	strcat(URI_TOTP, url_secret);
	strcat(URI_TOTP, "&period=30");

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode(URI_HOTP);
	displayQRcode(URI_TOTP);

	return (0);
}
