#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t hexToByte(char hex){
	return	 (hex>='0' && hex<='9') ? hex-'0':
		 (hex>='a' && hex<='f') ? hex-'a'+10:
		 (hex>='A' && hex<='F') ? hex-'A'+10:
		 0xff;
}

void padInfo(char *dest, char *accountName, char *issuer, char *secret_hex){

	char *tmp;
	char secret_bytes[10];
	char encode_buff[20];
	int i;

	//Concat strings
	strcat(dest, urlEncode(accountName) );

	tmp="?issuer=";
	strcat(dest, tmp);
	strcat(dest, urlEncode(issuer) );

	tmp="&secret=";
	strcat(dest, tmp);

	//Compute secret hex result
	memset(secret_bytes, 0, 10);
	memset(encode_buff, 0, 20);
	//Convert chars to bytes (20 char -> 10 byte) & encode (10 byte -> <=20 byte)
	for(i=0; i<10; i++)
		secret_bytes[i] = (hexToByte(secret_hex[2*i]) << 4) |
				   hexToByte(secret_hex[2*i + 1]) ;
	base32_encode(secret_bytes, 10, encode_buff, 20 );

	strcat(dest, encode_buff);
	
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
	char hotp[42+sizeof(issuer)+sizeof(accountName)+sizeof(secret_hex)];
	char totop[42+sizeof(issuer)+sizeof(accountName)+sizeof(secret_hex)];
	char *tmp;

	//Pad zeros
	memset(hotp, 0, sizeof(hotp));
	memset(totop, 0, sizeof(totop));

	//Info:hotp
	strcpy(hotp, "otpauth://hotp/");
	padInfo(hotp, accountName, issuer, secret_hex);
	tmp="&counter=1";
	strcat(hotp, tmp);

	//Info:totop
	strcpy(totop, "otpauth://totp/");
	padInfo(totop, accountName, issuer, secret_hex);
	tmp="&period=30";
	strcat(totop, tmp);

	//Display
	displayQRcode(hotp);
	displayQRcode(totop);

	return (0);
}

