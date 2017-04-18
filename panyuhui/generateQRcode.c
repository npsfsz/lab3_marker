#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define MAX_URI_SIZE  200
#define SECRET_KEY_SIZE  20
#define SECRET_KEY_SIZE_BASE32 16
#define SECRET_KEY_SIZE_IN_BYTE  10


char* generateURI(char *, char *, char *, int);
void convert_20hex_to_80bit(char *, uint8_t *);

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
	char *   secret_hex_2b_converted = malloc(sizeof(char) * 20);
	char *   hotp;
	char *   totp;
	int i;

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	// right pad secret_hex with 0's
	for( i = 0; i < strlen(secret_hex) ; i++ ){
		secret_hex_2b_converted[i] = secret_hex[i];
	}
	for( ; i < 20; i++){
		secret_hex_2b_converted[i] = '0';
	}

	hotp = generateURI(issuer, accountName, secret_hex_2b_converted, 0);
	totp = generateURI(issuer, accountName, secret_hex_2b_converted, 1);

	displayQRcode(hotp);
	displayQRcode(totp);

	free(hotp);
	free(totp);

	return (0);
}

char*
generateURI(char *issuer, char *accountName, char *secret_hex, int type){
	char *uri = malloc(sizeof(char) * MAX_URI_SIZE);
	uint8_t secret_hex_in_byte[SECRET_KEY_SIZE_IN_BYTE];
	char result[SECRET_KEY_SIZE_BASE32+1];
	
	// to make strcat safe after malloc
	uri[0] = '\0';
	result[SECRET_KEY_SIZE_BASE32] = '\0';

	strcat(uri, "otpauth://");
	if( type == 0){
		strcat(uri, "hotp/");
	}else{
		strcat(uri, "totp/");
	}
	strcat(uri, urlEncode(accountName));
	strcat(uri, "?issuer=");
	strcat(uri, urlEncode(issuer));
	strcat(uri, "&secret=");

	convert_20hex_to_80bit(secret_hex, secret_hex_in_byte);
	
	base32_encode(secret_hex_in_byte, 10, result, SECRET_KEY_SIZE_BASE32);

	strcat(uri, result);

	if (type == 0){
		strcat(uri, "&counter=1");
	}else{
		strcat(uri, "&period=30");
	}

	return uri;
}

void 
convert_20hex_to_80bit(char *secret_hex, uint8_t *secret_hex_in_byte){
	char temp_byte_value[3];
	int i;

	// to make strtol safe
	temp_byte_value[3] = '\0';

	for( i = 0 ; i < SECRET_KEY_SIZE_IN_BYTE ; i++ ){
		temp_byte_value[0] = secret_hex[i*2];
		temp_byte_value[1] = secret_hex[i*2+1];
		secret_hex_in_byte[i] = (uint8_t) strtol(temp_byte_value, (char **) NULL, 16);
	}
}