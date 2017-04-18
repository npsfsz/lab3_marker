#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"


/* Harjot Malhi, 999844824, harjotsingh.malhi@mail.utoronto.ca Atharva
   Atharva Naidu, 999633678, athu.naidu@mail.utoronto.ca */

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


	//Set up for padding
	int secret_len = strlen(secret_hex);
	char paddedSecret[20];
	int i;

	//Pad the secret if needed
	if (secret_len<20){
		for (i = 0; i < secret_len; i++)
			paddedSecret[i] = secret_hex[i];
		for (i = secret_len; i < 20; i++)
			paddedSecret[i] = '0';
	}
	else
		strcpy(paddedSecret, secret_hex);

	//Convert padded secret into byte array
	uint8_t secretByteArray[10];
	for (i = 0; i<10; i++)
		sscanf(paddedSecret + 2*i, "%02x", &secretByteArray[i]);
	
	//Encode the byte array in base 32
	uint8_t final[20];
	int n = base32_encode(secretByteArray, 10, final, 20);

	//Encode both the account name and the issuer
	char accEncoded[200];
	char issEncoded[200];
	
	strcpy(accEncoded, urlEncode(accountName));
	strcpy(issEncoded, urlEncode(issuer));

	//Create hotp and totp urls
	char hotp[200], totp[200];

	sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accEncoded, issEncoded, final);
	sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accEncoded, issEncoded, final);

	//Generate and display both QR codes and strings

	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}
