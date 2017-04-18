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

	//Encode special characters in Account Name and Issuer
	const char * fixedAccountName = urlEncode(accountName);
	const char * fixedIssuer = urlEncode(issuer);


	//Convert the Secret from a Hexadecimal String to a Hexadecimal Integer (stored in hex_bits)
	uint8_t hex_bits[10];
	char hex[3];
	int i;
	for (i = 0; i < 10; i++) {
		hex[0] = secret_hex[2 * i];
		hex[1] = secret_hex[2 * i + 1];
		hex[2] = '\0';
		hex_bits[i] = (unsigned int) strtoul(hex, NULL, 16);
	}
	
	//Convert the secret to base 32 String
	char secret_base32[17];
	int length = base32_encode(hex_bits, 10, secret_base32, 16);
	secret_base32[16] = '\0';

	//Create URI for the HOTP
	char URI_hotp[1000];
	strcpy(URI_hotp, "otpauth://hotp/");
	strcat(URI_hotp, fixedAccountName);
	strcat(URI_hotp, "?issuer=");
	strcat(URI_hotp, fixedIssuer);
	strcat(URI_hotp, "&secret=");
	strcat(URI_hotp, secret_base32);
	strcat(URI_hotp, "&counter=1");

	displayQRcode(URI_hotp);

	//Create URI for the TOTP
	char URI_totp[1000];	
	strcpy(URI_totp, "otpauth://totp/");
	strcat(URI_totp, fixedAccountName);
	strcat(URI_totp, "?issuer=");
	strcat(URI_totp, fixedIssuer);
	strcat(URI_totp, "&secret=");
	strcat(URI_totp, secret_base32);
	strcat(URI_totp, "&period=30");

	displayQRcode(URI_totp);

	return (0);
}
