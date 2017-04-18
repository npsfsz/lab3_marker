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

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	
	char encodedAccountName[100];
	char encodedIssuer[100];
	char encodedSecret[200];
	int i;	

	strcpy(encodedAccountName,urlEncode(accountName));
	strcpy(encodedIssuer,urlEncode(issuer));		
	
	if(strlen(secret_hex)<20)
	{
		int length = strlen(secret_hex);
		int lengthNeeded = 20 - length;	

		length = strlen(secret_hex);
		lengthNeeded = 20 - length;

		for(i=0;i<length;i++)
		{
			encodedSecret[i] = secret_hex[i];
		}

		for(i=length;i<20;i++)
		{
			encodedSecret[i] = '0';
			
		}
	}

	else
	{
		strcpy(encodedSecret, secret_hex);		
	}
	
   	uint8_t byteArray[10];
    	uint8_t byteArrayLen;
	uint8_t encodedByteArray[20];
	byteArrayLen = strlen(encodedSecret);

    	for (i = 0; i < (byteArrayLen/2); i++) 
    	{
       	 	sscanf(encodedSecret + 2*i , "%02x", &byteArray[i]);       
    	}
    	
	base32_encode(byteArray,10,encodedByteArray,20);

	//debugging
/*	
    printf("Debug:Now CONFIRMING imp: \n");
	for (i = 0; i < 10; i++) 
    {
       printf("bytearray %d: %x\n", i, byteArray[i]);
    }
*/
    
    
	char buf1[200];
	sprintf(buf1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodedAccountName, encodedIssuer, encodedByteArray);
	displayQRcode(buf1);

	char buf2[200];
	sprintf(buf2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAccountName, encodedIssuer, encodedByteArray);
	displayQRcode(buf2);

	return (0);
}
