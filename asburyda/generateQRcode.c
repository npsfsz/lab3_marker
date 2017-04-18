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
        int rv;
	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
        char* encodedAccountName;char* encodedIssuer;char* paddedSecret;
        uint8_t* encodedSecret;
        uint8_t byteArray[10];
        encodedAccountName = malloc(strlen(accountName));
        encodedIssuer = malloc(strlen(issuer));
        paddedSecret = malloc(20);
        encodedSecret = malloc(sizeof(uint8_t)*20);
        //encode special characters for the account name and issuer
        strcpy(encodedIssuer,urlEncode(issuer));
        strcpy(encodedAccountName,urlEncode(accountName));
        
	assert (strlen(secret_hex) <= 20);
        //pads the secret with 0's until it is 20 bytes long
        strcpy(paddedSecret,secret_hex);
        if(strlen(secret_hex) < 20) {
            int len = strlen(secret_hex);      
            unsigned i;
            for(i=len;i<20;i++){
                paddedSecret[i]='0';
            }
        }
        //convert the padded secret into a byte array
        unsigned i;
        for(i=0;i<10;i++){
            sscanf(paddedSecret,"%2hhx",&byteArray[i]);
            paddedSecret +=2;
        }
        
        //encode the secret
        rv = base32_encode(byteArray,10,encodedSecret,20);
        
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
        char hotp[100];
        snprintf(hotp,100,"otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",encodedAccountName,encodedIssuer,encodedSecret);
        displayQRcode(hotp);
        
        char totp[100];
        snprintf(totp,100,"otpauth://totp/%s?issuer=%s&secret=%s&period=30",encodedAccountName,encodedIssuer,encodedSecret);
        displayQRcode(totp);
        
        
        free(encodedIssuer);
        free(encodedAccountName);
        free(encodedSecret);
	return (0);
}
