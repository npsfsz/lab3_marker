#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

//convert string
uint8_t* text_to_hex(char* input, int* res_len);
int char_to_hex(char input);

uint8_t* text_to_hex(char* input, int* res_len){
	int len = strlen(input);
	// 2 char are 1 byte, in case key length is not byte alligned
	len = len/2 + len%2;
	*res_len = len;
	//allocate space for conversion
	uint8_t* result = malloc(len*sizeof(uint8_t));
	int i;
	for (i = 0; i < len; i++){
		result[i] = char_to_hex(input[i*2]);
		result[i] = result[i] << 4;
		if (char_to_hex(input[i*2+1]) != -1){
			result[i]+=char_to_hex(input[i*2+1]);
		}
	}
	return result;
}

int char_to_hex(char input){
	if(input > 47 && input < 58)
		return (input - 48);
	if(input > 64 && input < 71)
		return (input - 55);
	return -1;
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

	const char* encoded_issuer = urlEncode(issuer);
	const char* encoded_accountName = urlEncode(accountName);
	int secret_len;
	uint8_t* secret = text_to_hex(secret_hex, &secret_len);
	uint8_t encoded_secret[21];
	base32_encode(secret, secret_len, encoded_secret, 21);

	//generate hotp url
	char hotp_url[300];
	strcpy(hotp_url, "otpauth://hotp/");
	strcpy(&hotp_url[strlen(hotp_url)], encoded_accountName);
	strcpy(&hotp_url[strlen(hotp_url)], "?issuer=");
	strcpy(&hotp_url[strlen(hotp_url)], encoded_issuer);
	strcpy(&hotp_url[strlen(hotp_url)], "&secret=");
	strcpy(&hotp_url[strlen(hotp_url)], encoded_secret);
	strcpy(&hotp_url[strlen(hotp_url)], "&counter=1");

	//generate totp url
	char totp_url[300];
	strcpy(totp_url, "otpauth://totp/");
	strcpy(&totp_url[strlen(totp_url)], encoded_accountName);
	strcpy(&totp_url[strlen(totp_url)], "?issuer=");
	strcpy(&totp_url[strlen(totp_url)], encoded_issuer);
	strcpy(&totp_url[strlen(totp_url)], "&secret=");
	strcpy(&totp_url[strlen(totp_url)], encoded_secret);
	strcpy(&totp_url[strlen(totp_url)], "&period=30");

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	displayQRcode(hotp_url);
	displayQRcode(totp_url);

	return (0);
}
