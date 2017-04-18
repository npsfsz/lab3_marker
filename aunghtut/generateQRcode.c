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
	char hotp[100]; 
	char totp[100];

	//encode accountname
	char * accountname_encode = urlEncode(accountName);
	//printf("Account Name is %s\n", accountname_encode);

	//encode issuer
	char * issuer_encode = urlEncode(issuer);
	//printf("Issuer is %s\n", issuer_encode);

	//encode secret
	//int base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize)
	//converting into uint8_t array
	uint8_t data[10];
	int i;
	for (i = 0; i < 10 ; i++){
		sscanf(secret_hex, "%02x",&data[i]);
		secret_hex += 2;
	}

	uint8_t secret_encode[20]; //encoded secret
	base32_encode(data, 10, secret_encode, 20);
	//printf("Secret is %s\n", secret_encode);

	//writing to required strings
	snprintf(hotp, 100, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountname_encode, issuer_encode, secret_encode);
	snprintf(totp, 100, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountname_encode, issuer_encode, secret_encode);

	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}
