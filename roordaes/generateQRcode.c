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

	const char *	issuer = argv[1];
	const char *	accountName = argv[2];
	const char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);
        
        // Padd secret to 20 bytes
	char* secret_20char = (char*) (malloc(100));
        strcpy(secret_20char, secret_hex);
        int i;
        for (i = strlen(secret_hex); i < 20; i++) {
	  secret_20char[i] = '0';
	}
        secret_20char[20]='\0';
 
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_20char);

	const char *	issuer_n = urlEncode(issuer);
	const char *	accountName_n = urlEncode(accountName);
        
        uint8_t* in_uint = (uint8_t*) malloc(10);
        for (i=0;i<10;i++) {
          char curr[3];
          curr[0] = secret_hex[i*2];
          curr[1] = secret_hex[i*2+1];
          curr[2] = '\0';
	  in_uint[i] = strtol(curr,NULL,16);
	}       

        char secret_n[21];  
        uint8_t* out_uint = (uint8_t*) malloc(500);
        int res = base32_encode(in_uint, 10, (uint8_t*) secret_n, 20);
        secret_n[20] = '\0';
        // Assume final length doesn't exceed 1000...
        char * hot_path = (char *) malloc(1000);
        hot_path[0] = '\0';
        strcpy(hot_path,"otpauth://hotp/");
        strcat(hot_path,accountName_n);
        strcat(hot_path,"?issuer="); 
        strcat(hot_path,issuer_n);
        strcat(hot_path,"&secret="); 
        strcat(hot_path,secret_n);
        strcat(hot_path,"&counter=1");

        char * tot_path = (char *) malloc(strlen(issuer_n)+strlen(accountName_n)+55);
        tot_path[0] = '\0';
        strcpy(tot_path,"otpauth://hotp/");
        strcat(tot_path,accountName_n);
        strcat(tot_path,"?issuer=");   
        strcat(tot_path,issuer_n);
        strcat(tot_path,"&secret="); 
        strcat(tot_path,secret_n);
        strcat(tot_path,"&period=30");

	displayQRcode(hot_path);
	displayQRcode(tot_path);

	return (0);
}
