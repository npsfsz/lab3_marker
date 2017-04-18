#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define MAX_BUF_SIZE 3000

uint8_t HEXtoInt(char c) {
    if ('A' <= c && c <= 'F')
        c = c - 'A' + 10;
    else if ('a' <= c && c <= 'f')
        c = c - 'a' + 10;
    else if ('0' <= c && c <= '9')
        c = c - '0';
    return (uint8_t) c;
}

void convert_8bitChar_to_4bitChar(char *b8p, uint8_t *b4p) {
    int b8len = (int) strlen(b8p);
    int b4len = b8len / 2;
    int i;

    for (i = 0; i < b8len; i++) {
        b4p[i] = (HEXtoInt(*b8p) << 4 | HEXtoInt(*(b8p + 1)));
        b8p += 2;
    }
    b4p[b4len] = '\0';
}

int main(int argc, char * argv[]) {
    if (argc != 4) {
        printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
        return (-1);
    }

    char * issuer = argv[1];
    char * accountName = argv[2];
    char * secret_hex = argv[3];

    assert(strlen(secret_hex) <= 20);

    printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
            issuer, accountName, secret_hex);

    char HOTP_Buf[MAX_BUF_SIZE];
    char TOTP_Buf[MAX_BUF_SIZE];
    bzero(HOTP_Buf, MAX_BUF_SIZE);
    bzero(TOTP_Buf, MAX_BUF_SIZE);

    // Printing HOTP
    const char *encoded_issuer = urlEncode(issuer);
    const char *encoded_accountName = urlEncode(accountName);
    char encoded_secret_hex[MAX_BUF_SIZE];
    uint8_t secret_hex_4bit[MAX_BUF_SIZE];
    bzero(secret_hex_4bit, MAX_BUF_SIZE);
    bzero(encoded_secret_hex, MAX_BUF_SIZE);


    // 8 bit character >>> 4 bits character
    convert_8bitChar_to_4bitChar(secret_hex, secret_hex_4bit);

    int result = base32_encode(secret_hex_4bit, 10,
            (uint8_t *) encoded_secret_hex, MAX_BUF_SIZE);
    //10 byte length is 80 bits

    //Printing HOTP
    snprintf(HOTP_Buf, MAX_BUF_SIZE, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",
            encoded_accountName, encoded_issuer, encoded_secret_hex);
    displayQRcode(HOTP_Buf);

    //Printing TOTP
    snprintf(TOTP_Buf, MAX_BUF_SIZE, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",
            encoded_accountName, encoded_issuer, encoded_secret_hex);
    displayQRcode(TOTP_Buf);
    
    return (0);
}
