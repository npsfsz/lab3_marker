#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#define URL_SIZE 1000

int ascii_to_hex(char ascii) {
	char letter = tolower(ascii);
	if(letter >= '0' && letter <= '9') 
	    return letter - '0';
	if(letter >= 'a' && letter <= 'f') 
	    return letter - 'a' + 10; 
}

char hex_to_ascii(uint8_t byte) {
    if(byte <= 9)
        return '0' + byte;
    else
        return 'A' + (byte - 10);     
}

uint8_t * string_to_byte_arr(char * str) {
	int len = strlen(str); 
	uint8_t * data = malloc(len/2);
	int i, j;
	
	for (i = 0, j = 0; i < len - 1; i += 2) {
		data[j++] = (16 * ascii_to_hex(str[i])) + (ascii_to_hex(str[i+1]));
	}
	return data;
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

	// Create an otpauth:// URI and display a QR code that's compatible with Google Authenticator
	char * encodeAccountName;
	char * encodeIssuer;
	//char alby[100];
	uint8_t * result = malloc(30); 
	//int count = 0;

	encodeAccountName = urlEncode(accountName);
	encodeIssuer = urlEncode(issuer);
	char urlTOTP[URL_SIZE];
	char urlHOTP[URL_SIZE];
	

	uint8_t * data = string_to_byte_arr(secret_hex);
	int count = base32_encode(data, 10, result, 20);
	//count = base32_encode(secret_hex, strlen(secret_hex), alby, 100);

	snprintf(urlHOTP, URL_SIZE,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodeAccountName, encodeIssuer, result);
	displayQRcode(urlHOTP);

	snprintf(urlTOTP, URL_SIZE,"otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodeAccountName, encodeIssuer, result);
	displayQRcode(urlTOTP);


	return (0);
}
