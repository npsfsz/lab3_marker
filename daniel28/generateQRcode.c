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

	// Convert hex to ascii
	uint8_t secret_ascii[10];
	char temp[3];
	temp[2] = '\0';
	unsigned i = 0;
	for (i=0;i<20;i+=2){
		temp[0] = secret_hex[i];
		temp[1] = secret_hex[i+1];
		//printf("temp: %s\n", temp);
		//printf("%d\n", strtol(temp, NULL, 16));
		secret_ascii[i/2] = (uint8_t) strtol(temp, NULL, 16);
	}
	/* Debug
	for (i=0; i<10; i++){
		printf("%d\n", (int)secret_ascii[i]);
	}
	printf("\n");
	*/

	// Convert ascii to base32
	char secret_base32[20];
	base32_encode(secret_ascii, 10, secret_base32, 20);

	//printf("%s\n", secret_base32);

	// HOTP
	char hotp[500];
	sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", urlEncode(accountName), urlEncode(issuer), secret_base32);
	displayQRcode(hotp);

	// TOTP
	char totp[250];
	sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer), secret_base32);
	displayQRcode(totp);

	return (0);
}
