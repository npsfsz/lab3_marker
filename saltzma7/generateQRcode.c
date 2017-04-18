#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#include "lib/sha1.h"

void toHex(char * s_hex, uint8_t ** int_hex) {
	int i;
	bzero(*int_hex, 10);
	for (i = 0; i < 20; i++) {
		char c = s_hex[i];
		uint8_t c_mask;
		switch (c) {
			case '1': 
				c_mask = 0x01;
				break;
			case '2':
				c_mask = 0x02;
				break;
			case '3': 
				c_mask = 0x03;
				break;
			case '4':
				c_mask = 0x04;
				break;
			case '5':
				c_mask = 0x05;
				break;
			case '6':
				c_mask = 0x06;
				break;
			case '7':
				c_mask = 0x07;
				break;
			case '8':
				c_mask = 0x08;
				break;
			case '9':
				c_mask = 0x09;
				break;
			case 'A':
				c_mask = 0x0A;
				break;
			case 'B':
				c_mask = 0x0B;
				break;
			case 'C':
				c_mask = 0x0C;
				break;
			case 'D':
				c_mask = 0x0D;
				break;
			case 'E':
				c_mask = 0x0E;
				break;
			case 'F':
				c_mask = 0x0F;
				break;
			case '0':
				c_mask = 0x00;
				break;
		}
		if (i % 2 == 1) {
			(*int_hex)[i/2] = (*int_hex)[i/2] ^ c_mask;
		}
		else {
			(*int_hex)[i/2] = (*int_hex)[i/2] ^ c_mask << 4;
		}
	}
	return;
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
	
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	uint8_t * int_secret = malloc(10 * sizeof(uint8_t));
	char secret32[17];
	toHex(secret_hex, &int_secret);
	base32_encode(int_secret, 20, secret32, 16);
	secret32[16] = '\0';
	//printf("%d\n", base32_decode(secret_32, secret_decoded, 21));


	char hotp[200];
	char totp[200];

	snprintf(hotp, 200, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", urlEncode(accountName), urlEncode(issuer), secret32);
	snprintf(totp, 200, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer), secret32);

	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}


