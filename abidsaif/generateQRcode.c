 // Submission copy - 233pm
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int sze=64;

int hex_to_int (char c)
{
    if ((c >= '0') && (c <= '9'))
        return c - '0';
    if ((c >= 'A') && (c <= 'F'))
        return 10 + c - 'A';
    return -1;
}

const char* getHTOPURI(const char* accountName, const char* issuer,  const uint8_t* secret_hex) {
	char *res = malloc(500);
	sprintf(res, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",accountName,issuer,secret_hex);
	return (const char*) res;
}

const char* getTOTPURI(const char* accountName, const char* issuer,  const uint8_t* secret_hex) {
	char* res = malloc(500);
	sprintf(res, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName,issuer,secret_hex);
	return (const char*) res;
}

uint8_t* hexCharArrayToUint8Array(char* secret_hex) {
	int sze = strlen(secret_hex)/2; 
	 uint8_t *temp = malloc(strlen(secret_hex)/2);
	 int i=0;
	 uint8_t zero = 0;
	 for (i=0;i<sze;i++) {
		 temp[i] = zero;
	 }

	 uint8_t *head = temp;
	 int j =0;
	 for (i=0;i<strlen(secret_hex);i=i+2){
        uint8_t hex1 = (uint8_t)hex_to_int (secret_hex[i]);
        uint8_t hex2 = (uint8_t)hex_to_int (secret_hex[i+1]);
		// This is so if we have 1, 2 -> 0000 0001, 0000 0010 then hex1<<4|hex2 --> 0001 0010
        temp[j] = (hex1<<4|hex2);
		j++;
    }
	return head;
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

	// Step 1: Sanitize our input
	const char* sanitizedAccountName = urlEncode(accountName);
	const char* sanitizedIssuer = urlEncode(issuer);
	 uint8_t* encodedSecret = malloc(500);	 
	 // Encode out secret_hex into encodedSecret 
 	base32_encode(hexCharArrayToUint8Array(secret_hex), strlen(secret_hex), encodedSecret, 16);
	displayQRcode(getHTOPURI(sanitizedAccountName,sanitizedIssuer,encodedSecret));
	displayQRcode(getTOTPURI(sanitizedAccountName,sanitizedIssuer,encodedSecret));

	return (0);
}


