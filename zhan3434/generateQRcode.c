#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int toHex(char input)
{
    if(input<='z' && input>='a')
    {
        input = 'A' - 'a' + input;
    }

    return (input-'0'<=9) ? input-'0' : input-'A'+10;
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

        const char * encodedIssuer = urlEncode(issuer);
        const char * encodedName = urlEncode(accountName);

        char paddedStr[20] = "";
        memset(paddedStr,'0',20);
        strncpy(paddedStr,secret_hex,strlen(secret_hex));
        paddedStr[20] = '\0';

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n", encodedIssuer, encodedName, paddedStr);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//displayQRcode("otpauth://testing");

        int i,j;

        //int strToencode[10];

        char strNew[20]="";

        for(i=0,j=0; i<20; i+=2,j++)
        {
                strNew[j] = (char) (16*toHex(paddedStr[i])+toHex(paddedStr[i+1]));
        }

        char finalStr[20]="";

        base32_encode(strNew, 30, finalStr,16);

        int len = strlen(encodedName)+strlen(encodedIssuer)+strlen(finalStr)+strlen("otpauth://hotp/?issuer=&secret=&counter=1");
        char buf1[len],buf2[len];

        sprintf(buf1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodedName, encodedIssuer,finalStr);
        displayQRcode(buf1);

        sprintf(buf2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedName, encodedIssuer,finalStr);
        displayQRcode(buf2);
        
	return (0);
}
