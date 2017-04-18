#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t* ascii_hex_convert(char* input, size_t length,uint8_t* output);

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

	//starting:
	//otpauth://hotp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&counter=1
	char* encodedAccountName = urlEncode(accountName);
	char* encodedIssuer = urlEncode(issuer);

	//convert to hex
	//pad first

	char paddedSecret[21];
	int i=0, j=0, k=0;
	
	if(strlen(secret_hex) == 20){
		strncpy(paddedSecret, secret_hex, 21);
	}
	else{ //if not long enough

		for(i=0; i < strlen(secret_hex); i++){
			paddedSecret[i] = secret_hex[i];
		}
		for(i = strlen(secret_hex); i < 20 ; i++ ){
			paddedSecret[i] = '0';
		}

		//add null char
		paddedSecret[20] = 0;
	}


	uint8_t res[10];
	ascii_hex_convert(paddedSecret,20,res);


	char encodedSecret[16];
	base32_encode(res, 10, encodedSecret,16);

	char ticketBased[1024];
	snprintf(ticketBased, 1024,"otpauth://hotp/%s?issuer=%s&secret=", encodedAccountName, encodedIssuer);

	
	while(ticketBased[i] != NULL){
		i++;
	}

	for(j=0; j < sizeof(encodedSecret); j++){
		ticketBased[i+j] = encodedSecret[j];
	}

	char* endStr = "&counter=1";

	for(k=0; k < 10 ;k++ ){
		ticketBased[i+j+k] = endStr[k];
	}

	ticketBased[i+j+k] = NULL;

	displayQRcode(ticketBased);

	//otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30

	char timeBased[1024];
	snprintf(timeBased, 1024,"otpauth://totp/%s?issuer=%s&secret=", encodedAccountName, encodedIssuer);

	i=0;
	while(timeBased[i] != NULL){
		i++;
	}

	for(j=0; j < sizeof(encodedSecret); j++){
		timeBased[i+j] = encodedSecret[j];
	}

	endStr = "&period=30";

	for(k=0; k < 10 ;k++ ){
		timeBased[i+j+k] = endStr[k];
	}

	timeBased[i+j+k] = NULL;

	displayQRcode(timeBased);

	return (0);
}

uint8_t* ascii_hex_convert(char* input, size_t length, uint8_t* output)
{
    int i=0, j=0, high, low;

    for (; i < length; i+=2,++j) {
        high = input[i] > '9' ? input[i] - 'A' + 10 : input[i] - '0';
        low = input[i+1] > '9' ? input[i+1] - 'A' + 10 : input[i+1] - '0';

        output[j] = (high << 4 ) | low;
    }

    return output;
}