#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define URL_BUF_SIZE 100
#define HEX_LEN 20
#define HEX_BYTE_LEN (HEX_LEN / 2)

#define HOTP_URL_TEMPLATE "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1"
#define TOTP_URL_TEMPLATE "otpauth://totp/%s?issuer=%s&secret=%s&period=30"

int main(int argc, char **argv)
{
	if (argc != 4) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return -1;
	}

	char *issuer = argv[1];
	char *account_name = argv[2];
	char *secret_hex = argv[3];

	const int secret_hex_len = strlen(secret_hex);
	assert(secret_hex_len <= HEX_LEN);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		   issuer, account_name, secret_hex);

	const char *encoded_issuer = urlEncode(issuer);
	const char *encoded_account_name = urlEncode(account_name);

	// Left-pad secret hex
	char padded_secret_hex[HEX_LEN];
	memset(padded_secret_hex, '0', HEX_LEN - secret_hex_len);
	strncpy(&padded_secret_hex[HEX_LEN - secret_hex_len], secret_hex, secret_hex_len);

	// Get secret hex in bytes
	unsigned char secret_bytes[HEX_BYTE_LEN];
	sscanf(padded_secret_hex, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		   &secret_bytes[0], &secret_bytes[1], &secret_bytes[2],
		   &secret_bytes[3], &secret_bytes[4], &secret_bytes[5],
		   &secret_bytes[6], &secret_bytes[7], &secret_bytes[8], &secret_bytes[9]);

	char encoded_secret[HEX_LEN];
	(void) base32_encode(secret_bytes, HEX_BYTE_LEN, encoded_secret, HEX_LEN);
	
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char hotp_url_str[URL_BUF_SIZE], totp_url_str[URL_BUF_SIZE];

	snprintf(hotp_url_str, URL_BUF_SIZE, HOTP_URL_TEMPLATE,
			 encoded_account_name, encoded_issuer, encoded_secret);
	snprintf(totp_url_str, URL_BUF_SIZE, TOTP_URL_TEMPLATE,
			 encoded_account_name, encoded_issuer, encoded_secret);

	displayQRcode(hotp_url_str);
	displayQRcode(totp_url_str);

	return 0;
}
