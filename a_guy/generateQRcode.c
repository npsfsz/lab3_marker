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

        char *  issuer = argv[1];
        char *  accountName = argv[2];
        char *  secret_hex = argv[3];

        assert (strlen(secret_hex) <= 20);

        printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
                issuer, accountName, secret_hex);

    unsigned int bytes_secret[10];
    int i;
    for (i = 0; i < (strlen(secret_hex)/ 2); i++) {
        sscanf(secret_hex + 2*i, "%02x", &bytes_secret[i]);
        //printf("bytearray %d: %02x\n", i, bytes_secret[i]);
    }

    //printf("byte array conversion done\n");

    const char* encodedIssuer;
    encodedIssuer = urlEncode(issuer);

    //printf("encoded issuer: %s\n", encodedIssuer);

    const char* encodedAccountName;
    encodedAccountName = urlEncode(accountName);

    //printf("encoded accountName: %s\n", encodedAccountName);
    int x;
    uint8_t res[20];
    //int ncount;
    x = base32_encode((uint8_t *) bytes_secret,10,res,20);

    //int len = strlen()
    char hotpauth[100];
    int n = snprintf(hotpauth, 100, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",encodedAccountName,encodedIssuer,res);

    char totpauth[100];

    int m = snprintf(totpauth, 100, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",encodedAccountName,encodedIssuer,res);
    //printf("%s\n", hotpauth);
    displayQRcode(hotpauth);
    //printf("%s\n",totpauth);
    displayQRcode(totpauth);
        //otpauth://hotp/gibson?issuer=ECE568&secret=CI2FM6EQCI2FM6EQ&counter=1

        // Create an otpauth: URI and display a QR code that's compatible with Google Authenticator
        //
        //displayQRcode("otpauth://testing");
        //
                return (0);
}
        //
