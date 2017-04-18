#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define HEX_LEN		20
#define BYTE_LEN	10
#define HOTP_BASE_LEN	40	// Size of given base of hotp url + 1
#define TOTP_BASE_LEN	42	// Size of given base of totp url + 1


uint8_t asciiToHex(char input){
	switch(toupper(input)){
		        case '0': return 0;
			case '1': return 1;
			case '2': return 2;
			case '3': return 3;
			case '4': return 4;
			case '5': return 5;
			case '6': return 6;
			case '7': return 7;
			case '8': return 8;
			case '9': return 9;
			case 'A': return 10;
			case 'B': return 11;
			case 'C': return 12;
			case 'D': return 13;
			case 'E': return 14;
			case 'F': return 15; 			
	}		
}

void charToHex(char *input, uint8_t * output)
{
	int i;
	for(i=0; i<(strlen(input)/2); i++) 
		output[i] = (asciiToHex(*(input+ 2*i)) << 4) | asciiToHex(*(input+1 + 2*i));
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
	char * hotp_url;
	char * totp_url;



	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);


	char finalHex[strlen(secret_hex)];
	charToHex(secret_hex, finalHex);

	const char *encodedAccountName = urlEncode(accountName);
        const char *encodedIssuer = urlEncode(issuer);
        char encodedSecret[100];	// Store only 10 bytes of the base32 encoding so that we have an 80 bit secret

	int l = base32_encode((const uint8_t *) finalHex, 10, (uint8_t *) encodedSecret, 100);

	hotp_url = (char*) malloc(100*sizeof(char));
	totp_url = (char*) malloc(100*sizeof(char));


	snprintf(hotp_url, 100, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodedAccountName, encodedIssuer, encodedSecret);
	//printf(hotp_url);
	displayQRcode(hotp_url);
	
	snprintf(totp_url, 100, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAccountName, encodedIssuer, encodedSecret);
	displayQRcode(totp_url);
	free(hotp_url);
	free(totp_url);
	return (0);
}
