#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t * convertStringToByteArray(char * str) {
	uint8_t str_len = strlen(str);
	uint8_t * bytearray = malloc(str_len/2);
	int i;
	for (i = 0; i < (str_len / 2); i++) {
			sscanf(str + 2*i, "%2x", &bytearray[i]);
	}
	return bytearray;
}

char *format_otpauth(char *buf, char *issuer, char *accountName, char *secret_hex, char *type) {
	// Encode accountName and issuer
	const char *encodeAccountName = urlEncode(accountName);
	const char *encodeIssuer = urlEncode(issuer);
	uint8_t * result;
	result = (uint8_t *)malloc(sizeof(uint8_t) * 20);

	uint8_t *encoded_secret = convertStringToByteArray(secret_hex);
	int base32_count = base32_encode(encoded_secret, 10, result, 256);
	memset(buf, '\0', 1024 );
	
	if (strcmp(type, "hotp") == 0) {
		snprintf(buf, strlen(buf)-1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodeAccountName, encodeIssuer, result);
	} else if (strcmp(type, "totp") == 0) {
		snprintf(buf, strlen(buf)-1, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodeAccountName, encodeIssuer, result);
	}
	free(result);
	free(encoded_secret);
	return buf;
}

int main(int argc, char * argv[]) {
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
	char buf[1024];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	
	char *hotp_str = format_otpauth(buf, issuer, accountName, secret_hex, "hotp");
	displayQRcode(hotp_str);

	char *totp_str = format_otpauth(buf, issuer, accountName, secret_hex, "totp");
	displayQRcode(totp_str);

	return (0);
}

