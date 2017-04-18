#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define BOFF0(p) ((p >> 0) & 0xFF)
#define BOFF1(p) ((p >> 8) & 0xFF)
#define BOFF2(p) ((p >> 16) & 0xFF)
#define BOFF3(p) ((p >> 24) & 0xFF)

int main(int argc, char * argv[]) {
    if (argc != 4) {
        printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
        return (-1);
    }

    char * issuer = argv[1];
    char * accountName = argv[2];
    char * secret_hex = argv[3];

    size_t secret_hex_len = strlen(secret_hex);
    assert(secret_hex_len <= 20);

    printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
        issuer, accountName, secret_hex);

    // Create an otpauth:// URI and display a QR code that's compatible
    // with Google Authenticator
    unsigned secret_len = secret_hex_len;
    unsigned data_len = secret_hex_len/2;
    uint8_t secret[secret_len];
    uint8_t data[data_len];
    
    char conv[2];
    char* pEnd;
    unsigned i;
    for (i = 0; i < data_len; i++) {
        conv[0] = secret_hex[2 * i];
        conv[1] = secret_hex[2 * i + 1];
        data[i] = BOFF0(strtoul(conv, &pEnd, 16));
    }
    
    base32_encode((const uint8_t *) data, data_len, secret, secret_len);
    
    char hotp_url[100];
    char totp_url[100];
    sprintf(hotp_url, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", urlEncode(accountName), urlEncode(issuer), secret);
    sprintf(totp_url, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer), secret);
    displayQRcode(hotp_url);
    displayQRcode(totp_url);

    return (0);
}
