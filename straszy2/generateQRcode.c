#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

//this function takes the memory occupied by the secret (10 bytes) and replaces the ASCII value with its corresponding hex value 
//eg. if secret is 123, make binary -> 0001 0010 0011
uint8_t ASCII_to_hex(char c);
uint8_t ASCII_to_hex(char c){
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
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

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//Declare and Initialize Variables
	int len = 100;

	char * HOTP_URI = (char*)malloc(len*sizeof(char));
	char * TOTP_URI = (char*)malloc(len*sizeof(char));

	const char *en_accountName = urlEncode(accountName);
        const char *en_issuer = urlEncode(issuer);

	//convert secret
	//need to convert chars (secret) to binary array, size 10 because (20 chars * 4 bits) = (10 * 8 bits)
	uint8_t binary_key[10];
	int i;
	for(i=0;i<20;i+=2){
	   binary_key[i/2]=(ASCII_to_hex(secret_hex[i])*16 + ASCII_to_hex(secret_hex[i+1]));	
	   
	} 
	binary_key[10]='\0';

	//array to hold base32_encoded secret
	char en_secret[len];

	// call encoding function. 
	// use 10 for 2nd argument -> 80 bit secret
	int value = base32_encode((const uint8_t *)binary_key, 10, (uint8_t *)en_secret, len);
	
	//copy the correct string into the buffers using snprintf and then print both using given function
	snprintf(HOTP_URI, len, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", en_accountName, en_issuer, en_secret);
	snprintf(TOTP_URI, len, "otpauth://hotp/%s?issuer=%s&secret=%s&period=30", en_accountName, en_issuer, en_secret);
	displayQRcode(HOTP_URI);
	displayQRcode(TOTP_URI);

	//free allocated memory
	free(HOTP_URI);
	free(TOTP_URI);

	return (0);
}
