#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lib/encoding.h"

void char_2_hex(char *input, uint8_t * output){
	uint8_t  input_len = strlen(input) / 2;
	int i;
	for (i = 0; i < input_len; i++) 
        	sscanf(input + 2*i, "%02x", &output[i]);       
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
	int issuer_len = strlen(issuer);
	char encoded_issuer[issuer_len];
	int accountName_len = strlen(accountName);
	char encoded_accountName[accountName_len];
	int secret_hex_len = strlen(secret_hex);
	char padded_secret[20]; // Max is specified in lab3 doc
	char zero_pad = '0';
	int i,counter;
	uint8_t byte_buf[20]; // Will hold the bytes when converted from char to uint8_t
	char encoded_secret[100]; 
	char hotp[200];
	char totp[200];
	assert (secret_hex_len <= 20);
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	// URL encode Issuer and account name
	strcpy(encoded_issuer,urlEncode(issuer));
	strcpy(encoded_accountName,urlEncode(accountName));

	// Pad secret hex with 0's if length is less than 20
	if(secret_hex_len < 20){
		for(i=0;i<20;i++){
			if(i < secret_hex_len)
				padded_secret[i] = secret_hex[i];
			else
				padded_secret[i] = zero_pad;
		}
	}
	else
		strcpy(padded_secret, secret_hex);		
	//Convert padded secret from char array to uint8_t array
	char_2_hex(padded_secret,byte_buf);
	counter = base32_encode(byte_buf, 10 , (uint8_t *) encoded_secret, 100);
	// Construct QRcode buf
	sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_accountName, encoded_issuer, encoded_secret);
	sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_accountName, encoded_issuer, encoded_secret);
	displayQRcode(hotp);
	displayQRcode(totp);
	return (0);
}
