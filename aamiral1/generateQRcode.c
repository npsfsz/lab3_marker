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

	const char * encoded_account_name = urlEncode(accountName);
	const char * encoded_issuer = urlEncode(issuer);

	// 80 bit secret so only need 10 entries in array
	uint8_t secret_uint8[10];
	char * hex_chars = "0123456789ABCDEF";

	int i, j, k;
	int secret_int1, secret_int2;

	// iterate through secret_hex string (Note it is always 20 characters)
	for (i = 0, j = 0; i < 10; i++, j += 2) {

		secret_int1 = 0;
		secret_int2 = 0;


		for (k = 0; k < 16; k++) {
			if (secret_hex[j] == hex_chars[k]) {
				secret_int1 = k;
			}

			if (secret_hex[j+1] == hex_chars[k]) {
				secret_int2 = k;
			}

		}

		secret_uint8[i] = ((secret_int1<<4)&0x0f0) + ((secret_int2)&0x0f);

	}


	uint8_t result[20];

	int count = base32_encode(secret_uint8, 10, result, 20);

	char hotp_buf[250] = "\x0";
	char totp_buf[250] = "\x0";

	sprintf(hotp_buf, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_account_name, encoded_issuer, (char *)result);
	sprintf(totp_buf, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_account_name, encoded_issuer, (char *)result);


	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode(hotp_buf);
	displayQRcode(totp_buf);


	// displayQRcode("otpauth://testing");

	return (0);
}
