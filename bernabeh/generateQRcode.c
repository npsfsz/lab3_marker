#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#include "lib/sha1.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	//char * issuer = "ECE568";
	char *	accountName = argv[2];
	//char * accountName = "hein drik";
	char *	secret_hex = argv[3];
	//char * secret_hex = "123456789011";
	char * secret_result = "CI2FM6EQCI2FM6EQ";
	char * output;
	int time = 30;
	int counter = 1;
	size_t sz;
	size_t sz2;
	uint8_t converted_hex[10];

	// Pad secret_hex with 0's if less than 20.
	//printf("length of the secret hex: %d\n",strlen(secret_hex));
	char new_secret[20] = "";
	if (strlen(secret_hex)<20){
		int missing_zeroes = 20-(strlen(secret_hex));
		char zeroes[missing_zeroes];				
		int x;		
		for(x=0;x<missing_zeroes;x++){
			zeroes[x]= '0';		
		}
		zeroes[missing_zeroes]='\0';
		//printf("zeroes: %s\n",zeroes);
		strcat(new_secret,secret_hex);
		strcat(new_secret,zeroes);
		new_secret[20]='\0';
	}else{
		strcpy(new_secret,secret_hex);
	}
	//printf("length of the secret hex after padding: %d\n",strlen(new_secret));
	
	assert (strlen(new_secret) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, new_secret);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	// Convert Char* to uint*
	
 	int i;
	for (i = 0; i < (strlen(new_secret)/sizeof(new_secret[0]));i++){
		sscanf(new_secret + (2*i),"%2hhx",&converted_hex[i]);
	}
	
	// encode all the variables

	uint8_t result[20];
	base32_encode(converted_hex,10,result,20);
	//printf("Result: %s Count: %d\n",result,count);
	
	char convertedIssuer[strlen(issuer)];
	char convertedAccountName[strlen(accountName)];
	strcpy(convertedIssuer,urlEncode(issuer));
	strcpy(convertedAccountName,urlEncode(accountName));


	// Write the string into a char[] and send to display QR code
	sz = snprintf(NULL,0,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=%d",convertedAccountName,convertedIssuer,result,counter);
	char uri_link[sz];
	snprintf(uri_link,sz+1,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=%d",convertedAccountName,convertedIssuer,result,counter);	

	if (sz != '\0'){
		//printf("Size of string for QR: %zu\n",sz);	
	} else{
		printf("sz is Null\n");
	}
	displayQRcode(uri_link);

	sz2 = snprintf(NULL,0,"otpauth://totp/%s?issuer=%s&secret=%s&period=%d",convertedAccountName,convertedIssuer,result,time);
	char uri_link2[sz2];
	snprintf(uri_link2,sz2+1,"otpauth://totp/%s?issuer=%s&secret=%s&period=%d",convertedAccountName,convertedIssuer,result,time);	

	if (sz2 != '\0'){
		//printf("Size of string2 for QR: %zu\n",sz2);	
	} else{
		printf("sz2 is Null\n");
	}
	displayQRcode(uri_link2);
	return (0);
}

