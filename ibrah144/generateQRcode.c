#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#define MAX_LEN	128

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

	/* encode the account name and the issuer name. */
	char en_accountName[MAX_LEN];
	strncpy(en_accountName, urlEncode(accountName), MAX_LEN);

	char en_issuerName[MAX_LEN];
	strncpy(en_issuerName, urlEncode(issuer), MAX_LEN);


	char padded_secret[21];
	memset(padded_secret, '0', 20);

	/* Add padding if the secret is not 20 bytes. */
	if (strlen(secret_hex) < 20) {
		int i;
		for (i=0;i<strlen(secret_hex);i++) {
			padded_secret[i] = secret_hex[i];
		}
	}

	else {
		strncpy(padded_secret, secret_hex, 20);
	}

	/* Need to encode the secret, but first need to make it compatible
	with base32_encode(). Using http://stackoverflow.com/a/3409211 as a
	reference to translate the secret_hex to a byte array.*/
	
	char *pos = padded_secret;
	uint8_t data[10];
	int count;

	for (count=0; count<sizeof(data)/sizeof(data[0]); count++) {
		sscanf(pos, "%2hhx", &data[count]);
		pos += 2;
	}

	// printf("0x");
	// for (count=0; count<sizeof(data)/sizeof(data[0]); count++) {
	// 	printf("%02x", data[count]);
	// }
	// printf("\n");

	uint8_t en_secret[20];
	int code = base32_encode(data, 10, en_secret, 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	char hotp[400];
	snprintf(hotp, 400, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", \
				en_accountName, en_issuerName, en_secret);

	displayQRcode(hotp);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	char totp[400];
	snprintf(totp, 400, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", \
				en_accountName, en_issuerName, en_secret);
	displayQRcode(totp);

	return (0);
}
