#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

const char *  hotp_str = "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1";
const char *  totp_str = "otpauth://totp/%s?issuer=%s&secret=%s&period=30";

char * hex_to_base32_encode(char * secret) {
        char secret_hex[40];
        if (strlen(secret) % 2 != 0) {
            strcpy(secret_hex, "0");
            strcat(secret_hex, secret);
        } else {
            strcpy(secret_hex, secret);
        }

        // convert to uint8_t
        uint8_t val[40];
        size_t count = 0;
        int len = strlen(secret_hex) / 2;
        char * pos = secret_hex;
        for(count = 0; count < len; count++) {
             sscanf(pos, "%2hhx", &val[count]);
             pos += 2;
        }
        val[count] = '\0';

        char * secret_b32 = malloc(21); //secret in base 32 will be <= 20

        int secret_len = base32_encode(val, strlen(val), secret_b32, 21);
        assert(secret_len > 0);

        secret_b32 = realloc(secret_b32, strlen(secret_b32) + 1);
        return secret_b32;
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *  issuer = argv[1];
	char *  accountName = argv[2];
	char *  secret_hex = argv[3];
	char *  secret_b32;

	assert (strlen(secret_hex) <= 20);

        issuer = urlEncode(issuer);
        accountName = urlEncode(accountName);
        secret_b32 = hex_to_base32_encode(secret_hex);

        int buf_len = strlen(hotp_str) + strlen(issuer) + strlen(accountName) + strlen(secret_b32);

        char *buf1 = (char*) malloc(buf_len);
        snprintf(buf1, buf_len, hotp_str, accountName, issuer, secret_b32);
        char *buf2 = (char*) malloc(buf_len);
        snprintf(buf2, buf_len, totp_str, accountName, issuer, secret_b32);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode(buf1);
	displayQRcode(buf2);

        free(buf1);
        free(buf2);
        free(secret_b32);

	return (0);
}
