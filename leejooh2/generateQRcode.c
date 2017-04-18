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

	char * accountEncoded = urlEncode(accountName);
	char * issuerEncoded = urlEncode(issuer);

	//printf("DEBUG = accountEncoded: %s\nDEBUG = issuerEncoded: %s\n", accountEncoded, issuerEncoded);

	unsigned char padded_secret[20];
	int i = 0;

	strcpy(padded_secret, secret_hex);

	padded_secret[20] = '\0';
	//printf("DEBUG = padded: %s\n", padded_secret);

	const uint8_t byte_secret[10];

	for(i = 0; i < 10; i++)
	{
		sscanf(padded_secret + 2*i, "%02x", &byte_secret[i]);
		//printf("DEBUG = byte_secret %d: 0x%02d\n", i, byte_secret[i]);
	}

	uint8_t encoded_secret[20];
	int count = base32_encode(byte_secret, 10, encoded_secret, 20);

	// HOTP Ticket-Based
	char hotp_URI[200];

	sprintf(hotp_URI, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountEncoded, issuerEncoded, encoded_secret);

	//printf("DEBUG = hotp_URI: %s\nDEBUG = sizeof(hotp_URI): %d\n", hotp_URI, sizeof(hotp_URI));
	displayQRcode(hotp_URI);

	// TOTP Time-Based
	char totp_URI[200];

	sprintf(totp_URI, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountEncoded, issuerEncoded, encoded_secret);

	//printf("DEBUG = totp_URI: %s\nDEBUG = sizeof(totp_URI): %d\n", totp_URI, sizeof(totp_URI));
	displayQRcode(totp_URI);

	return (0);
}
