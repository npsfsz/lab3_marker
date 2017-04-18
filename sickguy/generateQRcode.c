#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define LEN 100
#define SECRET_LEN 200
#define BYTE_LEN 10
#define RESULT_LEN 20
#define QR_LEN 200

void convert_to_hex(uint8_t unit_secret_len, uint8_t byte_secret_len, char * secret_hex, uint8_t * byte_secret)
{
	int i = 0;
	char *loc = secret_hex;
	while(i < (unit_secret_len / byte_secret_len)){
		sscanf(loc, "%2hhx", &byte_secret[i]);
		loc += 2;
		i++;
	}
}


int main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n", issuer, accountName, secret_hex);

	const char * encoded_issuer;
	encoded_issuer = urlEncode(issuer);
	const char * encoded_accountName;
	encoded_accountName = urlEncode(accountName);

	uint8_t byte_secret[BYTE_LEN];
	uint8_t unit_secret_len = strlen(secret_hex);
	convert_to_hex(unit_secret_len, sizeof(byte_secret[0]), secret_hex, byte_secret);

	uint8_t result[RESULT_LEN];
	base32_encode(byte_secret, BYTE_LEN, result, RESULT_LEN);
	
	char qr1[QR_LEN];
	sprintf(qr1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_accountName, encoded_issuer, result);
	displayQRcode(qr1);

	char qr2[QR_LEN];
	sprintf(qr2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_accountName, encoded_issuer, result);
	displayQRcode(qr2);

	return (0);
}
