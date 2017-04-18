#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"


// Helper method to convert hex digit to integer.
unsigned int hexToInt(char in) 
{
	unsigned int out = 0;
	//Check if its a numeric digit
   if(in >= '0' && in <= '9') 
      out =  (in - '0');
  // Check alphabectic lower case digit
   if(in >= 'a' && in <= 'f') 
      out =  (in - 'a') + 10;
  // Check ALphabetic upper case alpha digit.
   if(in >= 'A' && in <= 'F') // upper-case alpha digit
      out =  (in - 'A') + 10;
   return out; 
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


	//Encode account name
	const char * account_name_encoded = urlEncode(accountName);
	//Encode issuer
	const char * issuer_encoded = urlEncode(issuer);

	// secret buffer with padded zero values
	char secret_zeroed[21];
	//Check if zero padding required
	if(strlen(secret_hex)< 20){
		//Compute number of zeroes required
		int diff = 20 - strlen(secret_hex);
		//Pad zeros
		int i = 0;
		for(i = 0; i < strlen(secret_hex); i++){
			secret_zeroed[i] = '0';
		}
		//Copy secret hex
		int z = 0;
		for(z = diff; z < 20; z++){
			secret_zeroed[z] = secret_hex[z];
		}
		//Add null termination
		secret_zeroed[20] = '\0';
		//Update secret hex to zero padded one
		secret_hex = secret_zeroed;
	}

	//Compute Byte array form of secret hex.
	const char * secret_hex_string = secret_hex;
	const char *byteIndex = secret_hex_string;
  	unsigned char secret_hex_byte_array[10];

	// get a byte from secret_hex per 8 bits.
	size_t i = 0;
	for(i = 0; i < 10 ; i++) {
		// get first 4 bits, then shift by 4 and plug in next 4 bits.
		secret_hex_byte_array[i] = (hexToInt(*byteIndex) << 4) | hexToInt(*(byteIndex+1)); 
		byteIndex += 2;
	}


	//Set up encoded secret buffer.
	uint8_t secret_encoded[20];
	//Encode the secret.
	base32_encode(secret_hex_byte_array, 10, secret_encoded, 16);

	//Compute buffer lengths for hotp and totp

	//Setup and display hotp qrcode.
	int hotp_buf_length = strlen(account_name_encoded) + strlen(issuer_encoded) + strlen((char*)secret_encoded);
	hotp_buf_length += 40;
	char * hotp_buf_url = (char*) malloc(hotp_buf_length*sizeof(char));
	sprintf(hotp_buf_url, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", account_name_encoded, issuer_encoded, secret_encoded);
	displayQRcode(hotp_buf_url);

	//Setup and display totp qrcode.
	int totp_buf_length = strlen(account_name_encoded) + strlen(issuer_encoded) + strlen((char*)secret_encoded);
	totp_buf_length += 41;
	char * totp_buf_url = (char*) malloc(totp_buf_length*sizeof(char));
	sprintf(totp_buf_url, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", account_name_encoded, issuer_encoded, secret_encoded);
	displayQRcode(totp_buf_url);


	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator


	//displayQRcode("otpauth://testing");

	return (0);
}
