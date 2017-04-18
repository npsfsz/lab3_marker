/*************************


	Lab 3.
	Created by: Peter Tanugraha


**************************/
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

	//printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		//issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char formattedIssuer[200];
	strcpy(formattedIssuer,urlEncode(issuer));
	
	char formattedaccountName[200];
	strcpy(formattedaccountName,urlEncode(accountName));

	//Since the handout mentioned that all the input values will be provided as a 20-character base-32 values, with all
	//Letters in uppercase, i shall not worry about invalid stupid inpu.
	char formattedSecret[200];
	strcpy(formattedSecret,secret_hex);
	
	//The base32-encode function has the following function headers
	//int base32_encode(const uint8_t *data, int length, uint8_t *result,int bufSize)
        uint8_t myByteArray[10];
    	int length= strlen(formattedSecret);
	int i;
	//Putting it into a byte stream
   	for (i = 0; i < (length / 2); i++) 
     		   sscanf(formattedSecret + 2*i, "%02x", &myByteArray[i]);       
    
	uint8_t finalResult[20];
	
        base32_encode(myByteArray,10,finalResult,20);
	printf("Printing Results \n");
	printf("%s",finalResult);

	char finalStringHOTP[250];
	char finalStringTOTP[250];

	
	sprintf(finalStringHOTP, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", formattedaccountName, formattedIssuer, finalResult);	
	sprintf(finalStringTOTP, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", formattedaccountName, formattedIssuer, finalResult);

	displayQRcode(finalStringHOTP);
	displayQRcode(finalStringTOTP);

	return (0);
}
