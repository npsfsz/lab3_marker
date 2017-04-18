#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[]) {
    if (argc != 4) {
        printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
        return (-1);
    }

    char * issuer = argv[1];
    char * accountName = argv[2];
    char * secret_hex = argv[3];

    assert(strlen(issuer) < 100);
    assert(strlen(accountName) < 100);
    assert(strlen(secret_hex) == 20); //changed since we only allow 20 bytes secret input

    printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
            issuer, accountName, secret_hex);

    // Create an otpauth:// URI and display a QR code that's compatible
    // with Google Authenticator


    int i;
    char newacc[100];
    char newiss[100];
    strcpy(newacc, urlEncode(accountName));
    strcpy(newiss, urlEncode(issuer));

    uint8_t sec_bytes[10];
    for (i = 0; i < 10; i++) {
        sscanf(secret_hex + 2 * i, "%02x", &sec_bytes[i]);
    }

    uint8_t newsec[21];
    base32_encode(sec_bytes, 10, newsec, 20);
    newsec[20] = 0;

    char buf[200];
    sprintf(buf, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", newacc, newiss, newsec);
    displayQRcode(buf);
    sprintf(buf, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", newacc, newiss, newsec);
    displayQRcode(buf);

    return (0);
}
