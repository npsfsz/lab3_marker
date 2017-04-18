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
	uint8_t secret[10],
		result[20];
	char	* encoded_account_name = urlEncode(accountName),
		* encoded_issuer = urlEncode(issuer);
	int 	i,
		append_len = strlen(encoded_account_name) + strlen(encoded_issuer) + 20;

	char *	issuer_path = "?issuer=\0",
	* t_path = "otpauth://totp/\0",
	* h_path = "otpauth://hotp/\0",
	* secret_path = "&secret=\0",
	* h_end = "&counter=1\0",
	* t_end = "&period=30\0";
	int len = 41;

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//Convert secret string to hex values
	for(i = 0; i < 19; i += 2){
		uint8_t 	v1 = secret_hex[i],
				v2 = secret_hex[i+1];
		if (v1 >= 'A')
			v1 -= 7;
		if (v2 >= 'A')
			v2 -= 7;
		secret[i/2] = ((v1 - 0x30) << 4) + (v2 - 0x30);
	}
	
	//Encode the secret
	assert (base32_encode(secret, 10, result, 20) != -1);
	
	//Create the QR code strings
	char * t_code;
	assert(t_code = malloc(sizeof(char)*(len+append_len+1)));
	t_code[0] = '\0';
	strcat(t_code, t_path);
	strcat(t_code, encoded_account_name);
	strcat(t_code, issuer_path);
	strcat(t_code, encoded_issuer);
	strcat(t_code, secret_path);
	strcat(t_code, result);
	strcat(t_code, t_end);

	char * h_code;
	assert(h_code = malloc(sizeof(char)*(len+append_len+1)));
	h_code[0] = '\0';
	strcat(h_code, h_path);
	strcat(h_code, encoded_account_name);
	strcat(h_code, issuer_path);
	strcat(h_code, encoded_issuer);
	strcat(h_code, secret_path);
	strcat(h_code, result);
	strcat(h_code, h_end);

	//Display the QR codes
	displayQRcode(h_code);
	displayQRcode(t_code);

	return (0);
}
