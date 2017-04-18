#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t charToHex(char p) {
	if (p >= '0' && p <= '9')
		return (p - '0');
	if (p >= 'A' && p <= 'F')
		return (p - 'A' + 10);
	
	// invalid character received
	return 1;
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

	//assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	
	// Encode the issuer and accountName
	char * acctName_encoded = (char*)urlEncode(accountName);
	char * issuer_encoded = (char*)urlEncode(issuer);
	
	int first_cp_len = (int)(strlen(secret_hex)/2);//rounding down
	int second_cp_len = (int)(strlen(secret_hex)/2)+1;//rounding up
	unsigned char converted_hex[second_cp_len];
	char *p = secret_hex;

	// Convert the hex char's into proper byte array
	// Since there are 20 hex chars and each is represented by 4 bits, need 10 bytes
	// Need to take pairs of 4 bit characters and group them into single 8 bit element
	int i = 0;
	for (i = 0; i < first_cp_len; i++) {
		unsigned char val1, val2;
		val1 = charToHex(*p);
		val2 = charToHex(*(p+1));
		converted_hex[i] = ((val1 << 4) | val2); // Combine the 2 hex chars into single 8 bit values		
		//printf("converted hex is 0x%hx\n", converted_hex[i]);
		p = p + 2; // Go to the next 2 hex values
	}
	
	if(first_cp_len*2 == strlen(secret_hex)){//given secret hex has even number of digits
		
		// printf("even number\n");
		converted_hex[first_cp_len] = '\0';
		converted_hex[second_cp_len] = '\0';
		
	}else if(first_cp_len*2+1 == strlen(secret_hex)){//given secret hex has odd number of digits
		
		//todo: need to test for odd numbers
		// printf("odd number\n");
		unsigned char val1 = charToHex(*p);
		unsigned char val2 = charToHex('0');
		converted_hex[first_cp_len] = ((val1 << 4) | val2);;
		converted_hex[first_cp_len+1] = '\0';
	}
	
	
	uint8_t * secret_encoded = malloc(128*sizeof(uint8_t));
	int bufSize = 128;
	
	// Encode the secret key, stored in secret_encded
	int count = base32_encode(converted_hex, 10, secret_encoded, bufSize);

	// Check the encoded string
	/* 	
	for (i = 0; i < count; i++) {
		printf("%c", secret_encoded[i]);
	}
	printf("\n"); 
	*/

	// Setup the URI for HOTP and TOTP string format
	char * auth_URI = malloc(256*sizeof(char));
	snprintf(auth_URI, 256, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", acctName_encoded, issuer_encoded, secret_encoded);
	displayQRcode(auth_URI); // Display the HOTP URI

	snprintf(auth_URI, 256, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", acctName_encoded, issuer_encoded, secret_encoded);
	displayQRcode(auth_URI); // Display the TOTP URI

	free(auth_URI);
	free(secret_encoded);

	return (0);
}
