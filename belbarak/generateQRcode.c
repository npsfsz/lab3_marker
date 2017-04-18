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
	
	char* s_hex= secret_hex;

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	const char* encodedIssuer=urlEncode(issuer);
	const char* encodedAccountName=urlEncode(accountName);
	
	char str_secret[20]="";
	
	//pad zeros to secret_hex
	int i;
	for(i=0; i<strlen(s_hex); i++){
		str_secret[i]=s_hex[i];
		}
		
	int j;
	for(j=strlen(s_hex); j<20; j++){
		str_secret[j]='0';
		}
		
	str_secret[20]='\0';
	strcpy(s_hex,str_secret);

	int k,l;
	int inner, outer;
	int total[10];
	char str_b32[20]="";
	for(k=0, l=0; k<20; k+=2, l+=1){
		if(s_hex[k]<= 57){
			inner=s_hex[k]-48;
			}
		else if(s_hex[k]<= 70){
			inner=s_hex[k]-55;
			}
		else if(s_hex[k]<= 102){
			inner=s_hex[k]-87;
			}
		
		if(s_hex[k+1]<= 57){
			outer=s_hex[k+1]-48;
			}
		else if(s_hex[k+1]<= 70){
			outer=s_hex[k+1]-55;
			}
		else if(s_hex[k+1]<= 102){
			outer=s_hex[k+1]-87;
			}
		total[l]=16*inner+ outer;
		str_b32[l]=(char)total[l];
		
		}
	char secret[20]="";
	base32_encode(str_b32, 20, secret, 16);
	
	char QR1[100];
	sprintf(QR1,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",encodedAccountName, encodedIssuer, secret);
	displayQRcode(QR1);
	
	char QR2[100];
	sprintf(QR2,"otpauth://totp/%s?issuer=%s&secret=%s&period=30",encodedAccountName, encodedIssuer, secret);
	displayQRcode(QR2);
	return (0);
}