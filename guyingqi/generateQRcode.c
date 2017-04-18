#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define TOP_LEN 100
#define SECRET_LEN 20

char * hex_convert(char *input) ;

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
        char htop_url[TOP_LEN+1] ;
        char totp_url[TOP_LEN+1] ;
        char padded_secret_str[SECRET_LEN+1] ;
        char encoded_secret[TOP_LEN+1] ;
        const char *encoded_accountName  ;
        const char *encoded_issuer ;
        char *hex_secret  ;
        int i , len;

        htop_url[TOP_LEN] = '\0' ;
        totp_url[TOP_LEN] = '\0' ;

        // encode account name
        encoded_accountName = urlEncode(accountName) ;

        // encode issuer name
        encoded_issuer = urlEncode(issuer) ; 

        // if secret code is not 20-byte long, pad '0' at the beginning
        for (i=0; i<SECRET_LEN; i++) 
            padded_secret_str[i] = '0' ;
        padded_secret_str[SECRET_LEN]='\0' ;

        len = strlen(secret_hex) ;
        strncpy(&padded_secret_str[SECRET_LEN-len], secret_hex, len) ;

        // convert the secret string to hex value
        // for example, input secret string is "1234567890", 
        // '1' is a character, not a hex value, 
        // we need to convert string '12' to a byte with hex value 0x12
        // then convert string '34' to a byte with hex value 0x34, and so on
        secret_hex = padded_secret_str ;
        secret_hex = hex_convert(secret_hex) ;

        // encode the secret key
        int l = base32_encode((const uint8_t *)secret_hex, 10, (uint8_t *) encoded_secret, 100);

        snprintf(htop_url, TOP_LEN, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_accountName, encoded_issuer, encoded_secret) ;
	displayQRcode(htop_url) ;
 
        snprintf(totp_url, TOP_LEN, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",encoded_accountName, encoded_issuer, encoded_secret) ; 
        displayQRcode(totp_url) ;

	return (0);
}


char * hex_convert(char *input) {
    int len=strlen(input) ;
    int i ;

    for (i=0; i<len; i++) {
        if (input[i] >= '0' && input[i] <= '9')
            input[i] = input[i] - '0' ;
        else if (input[i] >= 'A' && input[i] <= 'Z')
            input[i] = input[i] - 'A' + 10;
        else if (input[i] >= 'a' && input[i] <= 'z')
            input[i] = input[i] - 'a' + 10 ;
        else
            input[i] = '0' ;
        if (i % 2 == 0 )
                input[i] = input[i]<< 4 ;
        else {
                input[i] = input[i] | input[i-1] ;
                input[(i-1)/2] = input[i] ;
        }
    }
    
    input[SECRET_LEN/2] = '\0' ;
    return input ;
}

