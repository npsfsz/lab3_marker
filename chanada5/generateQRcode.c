#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

static int
hexToBinary(char c) {
	// convert secret to binary
	 switch(c){
         case '0': return 0b0000;
		 case '1': return 0b0001;
		 case '2': return 0b0010;
		 case '3': return 0b0011;
		 case '4': return 0b0100;
		 case '5': return 0b0101;
		 case '6': return 0b0110;
		 case '7': return 0b0111;
		 case '8': return 0b1000;
		 case '9': return 0b1001;
		 case 'A': return 0b1010;
		 case 'B': return 0b1011;
		 case 'C': return 0b1100;
		 case 'D': return 0b1101;
		 case 'E': return 0b1110;
		 case 'F': return 0b1111;
		 case 'a': return 0b1010;
		 case 'b': return 0b1011;
		 case 'c': return 0b1100;
		 case 'd': return 0b1101;
		 case 'e': return 0b1110;
		 case 'f': return 0b1111;
	 }
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = urlEncode(argv[1]);
	char *	accountName = urlEncode(argv[2]);
	char decoded_hex[21] = "";
    uint8_t bin_hex[10] = "";
	char encoded_hex[30] = "";

	assert (strlen(argv[3]) <= 20);

	int secretLen = strlen(argv[3]);
	if (secretLen < 20) {
		int i, j;
		for (i = 0; i < 20 - secretLen; i++) {
			decoded_hex[i] = '0';
		}
		for (i = 20 - secretLen, j = 0; i < 20; i++, j++) {
			decoded_hex[i] = argv[3][j];
		}
        decoded_hex[20] = '\0';
	} else {
		snprintf(decoded_hex, 21, argv[3]);
	}

    int k;
	for (k = 0; k < 10; k++) {
		bin_hex[k] = (hexToBinary(decoded_hex[2*k]) << 4) + hexToBinary(decoded_hex[2*k + 1]);
	}

	base32_encode(bin_hex, 10, encoded_hex, 30);
  
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, decoded_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	int len = strlen(issuer) + strlen(accountName) + strlen(encoded_hex) + 42;
	char *  hotp = (char*) malloc (sizeof(char) * len);
	char *  totp = (char*) malloc (sizeof(char) * len);
	snprintf(hotp, len, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountName, issuer, encoded_hex);
	snprintf(totp, len, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountName, issuer, encoded_hex);

	displayQRcode(hotp);
	displayQRcode(totp);

	free(hotp);
	free(totp);

	return (0);
}
