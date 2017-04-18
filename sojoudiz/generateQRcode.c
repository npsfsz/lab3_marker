#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t hex_val(char str){
	if(str >= '0' | str <= '9')
		return str-'0';
	else if(str >= 'A' | str <= 'Z')
		return str-'A'+10;
	else if(str >= 'a' | str <= 'z')
		return str - 'a' + 10;

	return -1;
}

void get_hex(char* value, uint8_t* res){
	int i;
	//uint8_t res[10];

	for(i = 0; i < 10 ; i = i+2){
		res[i] = 16 * hex_val(value[i]) + (hex_val(value[i+1]));
	}
	printf("%s\n", res);
	//return res;
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
	char * 	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//encode issuer
	char issuerEncoded[512];
	char accountNameEncoded[512];
	uint8_t secret_hex_encoded[20];

uint8_t secret[11];
int i;
int count = 0;
char* ptr = secret_hex;
for(i = 0; i < 10 ; i++){
	secret[i] = 16 * hex_val(*ptr) + (hex_val(*(ptr+1)));
	ptr = ptr+2;
}
secret[10] = '\0';


strcpy(issuerEncoded, urlEncode(issuer));
strcpy(accountNameEncoded, urlEncode(accountName));
base32_encode(secret, 10, secret_hex_encoded, 20);



	char hotp[1024];
	char totp[1024];
  sprintf(hotp, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",accountNameEncoded, issuerEncoded, secret_hex_encoded);
	sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",accountNameEncoded, issuerEncoded, secret_hex_encoded);


	displayQRcode(hotp);
	displayQRcode(totp);

	return (0);
}
