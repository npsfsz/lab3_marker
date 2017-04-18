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

	char encodedAccountName[50];
	char encodedIssuer[50];
	
	// encoding the account name and issuer with provided function
	//const char * urlEncode (const char * s) 
	strcpy(encodedAccountName, urlEncode(accountName));
	strcpy(encodedIssuer, urlEncode(issuer));
	
	// encoding the secret with the provided function
	uint8_t result[20];

	uint8_t array[10];
	int i, num;
	for(i = 0; i < 10; i++){
		sscanf(secret_hex + 2*i, "%02x", &array[i]);
	}

	//base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize)
	num = base32_encode(array, 10, result, 20);

	char hotp[100];
	char totp[100];

	sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",encodedAccountName, encodedIssuer, result);
	displayQRcode(hotp);

	sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",encodedAccountName, encodedIssuer, result);
	displayQRcode(totp);	
	

	return (0);
}
