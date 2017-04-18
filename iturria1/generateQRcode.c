#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define BUFFER_SIZE 200

char * otpauth_format_hotp(char *,char *,char *,int);
char * otpauth_format_totp(char *,char *,char *,int);
int convert_string_to_hex(char *,char *);
int ascii_decode_hex(char);

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
	char *secret = (char *)malloc(21);
	memset(secret,0,sizeof(secret));
	int count = convert_string_to_hex(secret_hex,secret);

	char *otpauth_hotp = otpauth_format_hotp(issuer,accountName,secret,count);
	char *otpauth_totp = otpauth_format_totp(issuer,accountName,secret,count);

	displayQRcode(otpauth_hotp);
	displayQRcode(otpauth_totp);
	
	return (0);
}

char *
otpauth_format_hotp(char *issuer,char *accountName,char *secret,int count){
	char *otpauth = (char *)malloc(BUFFER_SIZE);
	char *secret_32 = (char *)malloc(100);
	memset(secret_32,0,sizeof(secret_32));

	base32_encode(secret,count,secret_32,100);
	strcpy(otpauth,"otpauth://hotp/");
	strcat(otpauth,urlEncode(accountName));
	strcat(otpauth,"?issuer=");
	strcat(otpauth,urlEncode(issuer));
	strcat(otpauth,"&secret=");
	strcat(otpauth,secret_32);
	strcat(otpauth,"&counter=1");
	free(secret_32);
	return otpauth;

}

char *
otpauth_format_totp(char *issuer,char *accountName,char *secret,int count){
	char *otpauth = (char *)malloc(BUFFER_SIZE);
	char *secret_32 = (char *)malloc(100);
	memset(secret_32,0,sizeof(secret_32));

	base32_encode(secret,count,secret_32,100);
	strcpy(otpauth,"otpauth://totp/");
	strcat(otpauth,urlEncode(accountName));
	strcat(otpauth,"?issuer=");
	strcat(otpauth,urlEncode(issuer));
	strcat(otpauth,"&secret=");
	strcat(otpauth,secret_32);
	strcat(otpauth,"&period=30");
	free(secret_32);
	return otpauth;

}

int
convert_string_to_hex(char *input,char *output){
	int i,count=0;
	for(i=0;i<strlen(input);i+=2){
		if(i==0 && strlen(input)%2==1){
			output[0]=ascii_decode_hex(input[0]);
			i--;
			}
		else {
			output[count]=ascii_decode_hex(input[i])*16+ascii_decode_hex(input[i+1]);
		}
		count++;
	}
	return count;
}

int
ascii_decode_hex(char input){
	if(input >= '0' && input <= '9')
		return input-'0';
	else
		return input-55;
}
