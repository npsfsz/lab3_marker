#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "lib/sha1.h"

#define HMAC_LENGTH 20
#define PAD_LENGTH 64
#define COUNTER_LENGTH 8
#define TIME_STEP 30

void convert_8bitChar_to_4bitChar(char *b8p, uint8_t *b4p);

void generateHMAC(char *key, size_t keyLength, uint8_t *msg, size_t msgLength, uint8_t *hmac);

int generateOTP(uint8_t *hmac);

int validateHOTP(char *secret_hex, char *HOTP_string);

int validateTOTP(char *secret_hex, char *TOTP_string);

uint8_t HEXtoInt(char c);

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

void generateHMAC(char *key, size_t keyLength, uint8_t *msg, size_t msgLength, uint8_t *hmac) {

    // Step 1. Converting the key type from char* to unit8_t.
    size_t newKeyLength = keyLength / 2;
    uint8_t new_key[newKeyLength];
    convert_8bitChar_to_4bitChar(key, new_key);

    // Step2. XOR iPad with key
    unsigned char k_opad[PAD_LENGTH + 1], k_ipad[PAD_LENGTH + 1];
    bzero(k_ipad, PAD_LENGTH);
    bzero(k_opad, PAD_LENGTH);
    bcopy(new_key, k_ipad, newKeyLength);
    bcopy(new_key, k_opad, newKeyLength);
    k_ipad[PAD_LENGTH] = '\0', k_opad[PAD_LENGTH] = '\0';
    int i = 0;
    for (i = 0; i < PAD_LENGTH; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // Step3. Inner SHA1
    SHA1_INFO ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, PAD_LENGTH);
    sha1_update(&ctx, msg, (int) msgLength);
    sha1_final(&ctx, hmac);

    // Step4. Outer SHA1
    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, PAD_LENGTH);
    sha1_update(&ctx, hmac, HMAC_LENGTH);
    sha1_final(&ctx, hmac);
}

int generateOTP(uint8_t *hmac) {
    int offset = hmac[19] & 0xf;
    return ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16
            | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 1000000;
}

int validateHOTP(char *secret_hex, char *HOTP_string) {
    // Creating a counter variable & Setting the counter to 1.
    uint8_t message[COUNTER_LENGTH];
    bzero(message, COUNTER_LENGTH);
    message[COUNTER_LENGTH - 1] = 1;

    // Generating the HMAC value.
    uint8_t hmac[HMAC_LENGTH];
    generateHMAC(secret_hex, strlen(secret_hex), message, COUNTER_LENGTH, hmac);

    return generateOTP(hmac) == strtol(HOTP_string, NULL, 10);
}

int validateTOTP(char *secret_hex, char *TOTP_string) {
    // Creating a timestamp message
    uint8_t message[COUNTER_LENGTH];
    uint64_t t = ((unsigned long) time(NULL)) / TIME_STEP;
    t = __builtin_bswap64(t);
    memcpy(message, &t, COUNTER_LENGTH);

    // Generating the HMAC value.
    uint8_t hmac[HMAC_LENGTH];
    generateHMAC(secret_hex, strlen(secret_hex), message, COUNTER_LENGTH, hmac);

    return generateOTP(hmac) == strtol(TOTP_string, NULL, 10);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
        return (-1);
    }

    char *secret_hex = argv[1];
    char *HOTP_value = argv[2];
    char *TOTP_value = argv[3];

    assert(strlen(secret_hex) <= 20);
    assert(strlen(HOTP_value) == 6);
    assert(strlen(TOTP_value) == 6);

    printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
            secret_hex,
            HOTP_value,
            validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
            TOTP_value,
            validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

    return (0);
}


