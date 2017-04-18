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

	/* 
	 * Create an otpauth:// URI and display a QR code that's compatible
	 * with Google Authenticator 
	 */

	//encode both issuer and account name
	const char * issuer_enc = urlEncode(issuer); 
	const char * accountName_enc = urlEncode(accountName); 

	//convert secret from string to hex
	int len = strlen(secret_hex); 
	uint8_t secret_real_hex[len/2]; 
	int i; 
	for(i = 0; i < len/2; i++){
		//copy every two string characters to 1 hex value 
		sscanf((2*i)+secret_hex,"%2x",&secret_real_hex[i]); 
	}

	//base32 encode secret
	uint8_t * secret_enc = (uint8_t *)malloc(len*(sizeof(uint8_t))); 
	base32_encode(secret_real_hex,len/2, secret_enc,len); 

	//create URI string
	char uri_ticket[1000]; 
	char uri_time[1000]; 
	sprintf(uri_ticket,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",accountName_enc,
			issuer_enc,secret_enc);
	sprintf(uri_time,"otpauth://totp/%s?issuer=%s&secret=%s&period=30",accountName_enc,
			issuer_enc,secret_enc); 
	
	//print QRI codes to screen 
	displayQRcode(uri_ticket);
	displayQRcode(uri_time);

	return (0);
}
