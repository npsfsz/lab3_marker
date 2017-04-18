#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

char hex_convert(char c) {
    if (c >= '0' && c <= '9')
        return c - 48;
    else // upper case characters only
        return c - 65 + 10;
}

void get_secret_hex(char* secret_hex, char* string_hex) {
    int i;
    for (i = 0; i < strlen(string_hex); i += 2) {
        secret_hex[i / 2] = (hex_convert(string_hex[i]) << 4)
                        + hex_convert(string_hex[i+1]);
    }
    secret_hex[10] = '\0';
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = urlEncode(argv[1]);
	char *	accountName = urlEncode(argv[2]);
	assert (strlen(argv[3]) <= 20);

	char secret_hex[11]; // length >= 21 shouldn't matter.
    get_secret_hex(secret_hex, argv[3]);
    printf("secret hex: %s\n", secret_hex);

    char secret_key[21];
    base32_encode(secret_hex, strlen(secret_hex), secret_key, 20);
//     base32_encode("123", 3, secret_hex, 20);
//     printf("secret hex: %s\n", secret_hex);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		argv[1], argv[2], argv[3]);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

    // Calculate lengths.
    const size_t hotp_basic_len =
    strlen("otpauth://hotp/?issuer=&secret=&counter=1");
    const size_t hotp_total_len =
        hotp_basic_len + strlen(accountName) + strlen(issuer) +
        strlen(secret_key) + 1;

    const size_t totp_basic_len =
        strlen("otpauth://totp/?issuer=&secret=&period=30");
    const size_t totp_total_len =
        totp_basic_len + strlen(accountName) + strlen(issuer) +
        strlen(secret_key) + 1;

    char hotp[hotp_total_len], totp[totp_total_len];

    sprintf(
        hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName,
        issuer, secret_key);
    sprintf(
        totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName,
        issuer, secret_key);

	displayQRcode(hotp);
	displayQRcode(totp);

    //char buf[30];
    //base32_decode(secret_hex, buf, 29);
    //printf("%s\n", argv[3]);
    //printf("%s\n", buf);

	return (0);
}
