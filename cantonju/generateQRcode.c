#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

void createString(char* padded_secret_hex, uint8_t* data){
	int i;
	
	// padded_secret_hex is 20 bytes, we want to make it 10 bytes
	// Loop and take 2 bytes and put it into data
	for(i = 0; i < 11 ; i++) {
        sscanf(padded_secret_hex, "%2hhx", &data[i]);
    	padded_secret_hex += 2;
    }

    data[i] = '\0';
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char * issuer = argv[1];
	char * accountName = argv[2];
	char * secret_hex = argv[3];
	char padded_secret_hex[21], encoded_secret[17], buf[256];
	int i;
	uint8_t data[11];

	assert(strlen(secret_hex) <= 20);

	// Copy the secret into another char array that we can pad if necessary
	strcpy(padded_secret_hex, secret_hex);
	
	// Pad the secret with spaces if the length is less than 20
	while (strlen(padded_secret_hex) < 20) {
		padded_secret_hex[strlen(padded_secret_hex)] = ' ';
	}

	padded_secret_hex[20] = '\0';

	// Since base32_encode needs uint, convert char * into uint
	createString(padded_secret_hex, data);

	// Encode the string
	base32_encode(data,strlen(data), encoded_secret, 16);
	encoded_secret[16] = '\0';

	// urlEncode the issuer and accountName
	const char * issuer_URL = urlEncode(issuer);
	const char * account_URL = urlEncode(accountName);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n", issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible with Google Authenticator

	// Set buf to empty
	memset(&buf[0], 0, sizeof(buf));

	// Print the HOTP otpath into buf
	snprintf(buf, sizeof(buf), "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", account_URL, issuer_URL, encoded_secret);
	
	// Display the QR code
	displayQRcode(buf);
	
	// Set buf to empty
	memset(&buf[0], 0, sizeof(buf));

	// Print the TOTP otpath into buf
	snprintf(buf, sizeof(buf), "otpauth://totp/%s?issuer=%s&secret=%s&period=30", account_URL, issuer_URL, encoded_secret);
	
	// Display the QR code
	displayQRcode(buf);

	return (0);
}
