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
	char *	secret_hex = argv[3]; //assume 20 character - no need to check for if odd
	const char * encodedAccountName;
	const char * encodedIssuer;
	char * strTOTP;
	char * strHOTP;

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	//Encode the parameters
	encodedAccountName = urlEncode(accountName);
	encodedIssuer = urlEncode(issuer);
	
	//Since the encoder only accepts 8 bit ints we need to convert the char (4 bits) into the hex
	//20 characters -> 10 8 bit int
	uint8_t secretTemp[10];
	int i;
	for (i = 0; i < strlen(secret_hex)/2; i++){
		//http://stackoverflow.com/questions/33982870/how-to-convert-char-array-to-hexadecimal
		secretTemp[i] = ('A' <= secret_hex[i*2] && secret_hex[i*2] <= 'F'  ? (10 + secret_hex[i*2] - 'A'):(secret_hex[i*2] - '0'))<<4 |  
			('A' <= secret_hex[i*2+1] && secret_hex[i*2+1] <= 'F'  ? (10 + secret_hex[i*2+1] - 'A'):(secret_hex[i*2+1] - '0'));
	}

	//for (i = 0; i < 10; i++){
	//	printf("x%d - %x\n", i, secretTemp[i]);
	//}

	//length = 10 bytes (80/8)
	//bufSize = 17 - 16 base-32 values + null terminator
	uint8_t encodedSecret[17];
	base32_encode(secretTemp, 10, encodedSecret, 17);

	//printf("\nEncoded Issuer: %s\nEncoded Account Name: %s\nEncoded Secret (Hex): %s\n\n",
	//	encodedIssuer, encodedAccountName, encodedSecret);

	//Copy all encoded information into TOTP and HOTP string
	int keyLen = 42 + strlen(encodedAccountName) + strlen(encodedIssuer) + strlen(encodedSecret); 

	strTOTP = (char*) malloc(sizeof(char) * keyLen);
	strHOTP = (char*) malloc(sizeof(char) * keyLen);
	strTOTP[keyLen - 1] = '\0';
	strHOTP[keyLen - 1] = '\0';

	snprintf(strHOTP, keyLen, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", 
			encodedAccountName, encodedIssuer, encodedSecret);
	snprintf(strTOTP, keyLen, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", 
			encodedAccountName, encodedIssuer, encodedSecret);

	//printf("TOTP : %s\n", strTOTP);
	//printf("HOTP : %s\n", strHOTP);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	//displayQRcode("otpauth://testing");

	//TOTP otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
	
	////HOTP otpauth://hotp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&counter=1
	displayQRcode(strHOTP);
	displayQRcode(strTOTP);

	free(strHOTP);
	free(strTOTP);

	return (0);
}
