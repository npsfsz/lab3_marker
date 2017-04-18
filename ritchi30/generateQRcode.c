#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

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

	// Some arbitrary long length
	char hotp_URI[257];
	char totp_URI[257];

	uint8_t secret_num_array[10];
	char hex_digit[3] = "00\0";

	int i;
	
	char *pEnd;

	// instead of an ASCII string that contains the secret encoded as
	// hexadecimal characters, we want an array of bytes corresponding
	// to the value of each hexadecimal digit

	// NOTE: discards any single hanging characters at the end of secret_hex
	for (i=0; i < strlen(secret_hex)/2; i += 1){
		hex_digit[0] = secret_hex[2*i];
		hex_digit[1] = secret_hex[2*i+1];
		secret_num_array[i] = strtol(hex_digit,&pEnd,16);
		//printf("%x\n", secret_num_array[i]);
	}

	uint8_t secret_32[10];
	// function signature: int base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize)
	base32_encode(secret_num_array, strlen(secret_hex)/2, secret_32, 20);

	sprintf(hotp_URI,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=1\0",urlEncode(accountName),urlEncode(issuer),secret_32);
	sprintf(totp_URI,"otpauth://totp/%s?issuer=%s&secret=%s&period=30\0",urlEncode(accountName),urlEncode(issuer),secret_32);
	
	displayQRcode(hotp_URI);
	displayQRcode(totp_URI);

	return (0);
}
