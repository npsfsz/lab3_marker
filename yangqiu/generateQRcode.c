#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define SECRETE_SIZE 20

int hex_char_to_int(char hex)
{
	return (hex<='9') ? (hex-'0') : (hex-'A'+10);
}

void decode_ascii_hex(char* hex_str)
{
	int i, j;

	i = 0;
	j = 0;
	while (i < strlen(hex_str)/2) {
		int low, high;
		high = hex_char_to_int(hex_str[j]);
		j++;
		low = hex_char_to_int(hex_str[j]);
		j++;
		hex_str[i] = low + (high << 4);
		i++;
	}
}

int
main(int argc, char * argv[])
{
	int r;

	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
	const char *issuer_url = urlEncode(issuer);
	const char *accountName_url = urlEncode(accountName);
	char secret_hex_base32[20];
	char hotp_url[128];
	char totp_url[128];

	assert (strlen(secret_hex) == 20);

	decode_ascii_hex(secret_hex);

	r = base32_encode(secret_hex, SECRETE_SIZE/2, secret_hex_base32,
	                  sizeof(secret_hex_base32));

	if (r < 0)
		return r;

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	snprintf(hotp_url, sizeof(hotp_url), "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName_url, issuer_url, secret_hex_base32);
	snprintf(totp_url, sizeof(hotp_url), "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName_url, issuer_url, secret_hex_base32);

	//displayQRcode("otpauth://testing");
	displayQRcode(hotp_url);
	displayQRcode(totp_url);

	return (0);
}
