#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define FIELD_LENGTH 20
#define SECRET_SIZE 40
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
	/*Generate Issuer*/
	const char *issuer_field = urlEncode(issuer);
	// printf("%s\n", issuer_field);

	/*Generate Account Name*/
	const char *accountName_field = urlEncode(accountName);
	// printf("%s\n", accountName_field);

	/*Encode secret:*/
	char secret[SECRET_SIZE];//Used to hold the secret result.
	char Byte_Array[FIELD_LENGTH/2];//Used to convert the argument (16-based number expressed by char) into byte value of the int.
	int i;
	for (i = 0; i < FIELD_LENGTH/2; ++i)
	{
		sscanf(secret_hex + 2*i, "%02x", &Byte_Array[i]);
	}
	base32_encode(Byte_Array, FIELD_LENGTH/2, secret, SECRET_SIZE);
	// printf("%s\n", secret);

	char * URI_HOTP = (char *)malloc(strlen(issuer_field) + strlen(accountName_field) + strlen(secret) + 100);//100 byte for other characters, should be enough with 45 
	char * URI_TOTP = (char *)malloc(strlen(issuer_field) + strlen(accountName_field) + strlen(secret) + 100);
	sprintf(URI_HOTP, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName_field, issuer_field, secret);
	sprintf(URI_TOTP, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName_field, issuer_field, secret);

	// with Google Authenticator

	displayQRcode(URI_HOTP);
	displayQRcode(URI_TOTP);

	free(URI_HOTP);
	free(URI_TOTP);
	
	return (0);
}
