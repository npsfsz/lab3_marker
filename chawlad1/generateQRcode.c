#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "lib/encoding.h"

int 
ascii_to_hex(char c)
{
	c = toupper(c);
	if (c >= 'A') return c - 'A' + 10;
	else return c - '0';
}

char*
encode_secret(char* secret_hex)
{
	char padded_secret[21];
	memset(padded_secret, '\0', 21);
	strcpy(padded_secret, secret_hex);

	int i;
	for(i = strlen(secret_hex); i < 20; i++) {
		padded_secret[i] = '0';
	}

	uint8_t secret_8bit[10];

	int j = 0;
	for(i = 0; i < 20; i += 2) {
		secret_8bit[j++] = 16*ascii_to_hex(padded_secret[i]) + ascii_to_hex(padded_secret[i+1]);
	}

	uint8_t* secret_encoded = malloc(21);
	int count = base32_encode(secret_8bit, 10, secret_encoded, 20);
	return secret_encoded;
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

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	const char* issuer_encoded = urlEncode(issuer);
	const char* accountName_encoded = urlEncode(accountName);
	char* secret_encoded = encode_secret(secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	char hotp_str[128];
	snprintf(hotp_str, 128, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", 
		accountName_encoded, issuer_encoded, secret_encoded);
	displayQRcode(hotp_str);

	char totp_str[128];
	snprintf(totp_str, 128, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", 
		accountName_encoded, issuer_encoded, secret_encoded);
	displayQRcode(totp_str); 

	free(secret_encoded);

	return (0);
}
