#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "lib/encoding.h"
#define SECRET_KEY_BIT_LENTH 80


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
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n", issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	
	const char * issuer_encode = urlEncode(issuer);
	const char * accountName_encode = urlEncode(accountName);
	// 80bits corresponds to 16digit base32 number
	int hex_length = strlen(secret_hex);
	char pad_secret_hex[SECRET_KEY_BIT_LENTH/4+1];	
	uint8_t unit8_array[(SECRET_KEY_BIT_LENTH/8)];
	int integer_array[SECRET_KEY_BIT_LENTH/4];
	char * hex_lookup_table = "0123456789ABCDEF";
	int final_len = SECRET_KEY_BIT_LENTH/5 + strlen(issuer_encode) + strlen(accountName_encode) + 128;
	char hotp[final_len];
	char totp[final_len];
	int i, j;
	
	//need to pad 0s in the end if not 20 hex digits
	strncpy (pad_secret_hex, secret_hex,hex_length);
	for(i=hex_length; i<20; i++){
		pad_secret_hex[i] = '0';
	}
	pad_secret_hex[i]='\0';

	for(i = 0; i < 20 ; i ++){
		char digit_char = pad_secret_hex[i];
		integer_array[i] = -98;//magic number
		for(j = 0; j < 16; j ++){
			if(toupper(digit_char) == hex_lookup_table[j]){
				integer_array[i] = j;
				j=16;
			}
		}
	}

	i = 0;
	j = 0;

	for (i = 0; i < SECRET_KEY_BIT_LENTH/4; i ++){
		if(integer_array < 0){
			printf("Translate to integer failed.\n");
			return -1;
		}
	}
	
	//convert to uint8
	for(i = 0; i < 20; i= i+2){
		if((i+2)%2 == 0){
			unit8_array[j] = (((integer_array[i]<<4)&0x0f0) + (integer_array[i+1]&0x0f))&0x0ff;
			j ++;
		}
	}

	uint8_t *base32 = (uint8_t*) malloc(sizeof(uint8_t)*(SECRET_KEY_BIT_LENTH/5));
	base32_encode(unit8_array, SECRET_KEY_BIT_LENTH/4, base32, (SECRET_KEY_BIT_LENTH/5));
	sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName_encode, issuer_encode, base32);
	sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName_encode, issuer_encode, base32);
	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}
