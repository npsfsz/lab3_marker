#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define BUF_SIZE 2048
#define SECRET_HEX_SIZE 20


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

	int i = 0;
	char buf[BUF_SIZE];
	char secretHex_padded[BUF_SIZE]; 

	const char * encoded_issuer = urlEncode(issuer);
	const char * encoded_accountName = urlEncode(accountName);
	
	strcpy(secretHex_padded, secret_hex);

	for(i = 0; i < SECRET_HEX_SIZE -strlen(secret_hex) ; i++ ){
		secretHex_padded[i + strlen(secret_hex)] = '0';
	}
	secretHex_padded[i + strlen(secret_hex)] = '\0';


	uint8_t secret_buf[20/2];
	uint8_t encoded_secret_buf[20];

	for(i = 0; i < 20/2; i++){
		sscanf(secretHex_padded + 2*i, "%02x", &secret_buf[i]);       

	}

	base32_encode(secret_buf, 10, encoded_secret_buf, 20);

	snprintf(buf, BUF_SIZE, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",encoded_accountName ,encoded_issuer ,encoded_secret_buf );
	displayQRcode(buf);

	snprintf(buf, BUF_SIZE, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",encoded_accountName ,encoded_issuer ,encoded_secret_buf );
	displayQRcode(buf);

	return (0);
}
