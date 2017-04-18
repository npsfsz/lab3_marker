#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "lib/encoding.h"

#define HS_LENGTH 20

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

	int secret_hex_len = strlen(secret_hex);
	uint8_t unit8_secret_hex[HS_LENGTH/2];
	
	int i,j;

	int integer_secret_hex[secret_hex_len];
	char * ref = "0123456789ABCDEF";

	char* hotp_format = "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1";
	char* totp_format = "otpauth://totp/%s?issuer=%s&secret=%s&period=30";

	int offset = 20 - secret_hex_len;

	// if secret_hex_len is less than 20 bytes, padd its front with 0

	for(i = 0; i < offset; i ++){
			integer_secret_hex[i] = 0;
		}

	// convert secret_hex from str to int array
	for(i = offset; i<20; i++)
	{
		char temp = secret_hex[i-offset];
		integer_secret_hex[i] = -1;
		for( j=0; j<16; j++)
		{
			if(toupper(temp) == ref[j])
			{
			integer_secret_hex[i] = j;
			break;
			}
		}
	}

	for(i = 0; i<20; i++)
	{
		assert(integer_secret_hex[i] >= 0);
	}

	// convert integer_secret_hex to unit8 array
	j = 0;
	for( i=0; i<20; i = i+2)
	{
		if((i+2)%2 == 0)
		{
			unit8_secret_hex[j] = ((integer_secret_hex[i]<<4) & 0x0f0) + (integer_secret_hex[i+1] & 0x0f);
			unit8_secret_hex[j] = unit8_secret_hex[j] & 0x0ff;
			j++;
		}
	}

	char encoded_accountName[200];
	char encoded_issuer[200];
	strncpy(encoded_accountName, urlEncode(accountName),200);
	strncpy(encoded_issuer,urlEncode(issuer),200);

	uint8_t *encoded_secret_hex = (uint8_t*) malloc(sizeof(uint8_t)*16);
	base32_encode(unit8_secret_hex, 20, encoded_secret_hex, 16);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator


	char hotp_url[200];
	char totp_url[200];	
	
	sprintf(hotp_url, hotp_format, encoded_accountName, encoded_issuer, encoded_secret_hex);
	displayQRcode(hotp_url);

	// TOTP
	sprintf(totp_url, totp_format, encoded_accountName, encoded_issuer, encoded_secret_hex);
	displayQRcode(totp_url);

	return (0);
}
