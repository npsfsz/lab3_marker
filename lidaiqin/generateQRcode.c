#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t
toHex(char* c)
{
		uint8_t h1 = (c[0] >= '0' && c[0] <= '9') ? c[0] - '0' : c[0] - 'A' + 10;
		uint8_t h2 = (c[1] >= '0' && c[1] <= '9') ? c[1] - '0' : c[1] - 'A' + 10;

		uint8_t res = h1 * 16 + h2;
		return res;
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

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	uint8_t secret_buf[10];
	int i;
	for (i = 0; i < 10; i++)
		secret_buf[i] = toHex(&secret_hex[2*i]);
	uint8_t secret_encode[25];
	int res = base32_encode(secret_buf, 10, secret_encode, 25);

	char* HOTP_STRING;
	asprintf(&HOTP_STRING, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", urlEncode(accountName), urlEncode(issuer), secret_encode);
	char* TOTP_STRING;
	asprintf(&TOTP_STRING, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer), secret_encode);
	displayQRcode(HOTP_STRING);
	displayQRcode(TOTP_STRING);

	return (0);
}
