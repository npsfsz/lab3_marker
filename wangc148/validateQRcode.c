#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "lib/sha1.h"
#define BLOCK_SIZE 64

void getHmac(uint8_t *key, uint8_t *m, uint8_t * result) {
    int i;

    uint8_t padded_key[BLOCK_SIZE];
    bzero(&padded_key, BLOCK_SIZE);
    memcpy(padded_key, key, 10); //80 bit long key

    uint8_t opaded_key[BLOCK_SIZE];
    uint8_t ipaded_key[BLOCK_SIZE];

    for (i = 0; i < BLOCK_SIZE; i++) {
        opaded_key[i] = 0x5c ^ padded_key[i];
        ipaded_key[i] = 0x36 ^ padded_key[i];
    }

    SHA1_INFO ctx;
    uint8_t inner[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_update(&ctx, ipaded_key, BLOCK_SIZE);
    sha1_update(&ctx, m, 8); //the message here is 8 bytes
    sha1_final(&ctx, inner);

    sha1_init(&ctx);
    sha1_update(&ctx, opaded_key, BLOCK_SIZE);
    sha1_update(&ctx, inner, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, result);
}

int dynamicTruncation(uint8_t *hmac_result) { //directly copied from handout.
    int offset = hmac_result[19] & 0xf;
    int bin_code = (hmac_result[offset] & 0x7f) << 24
            | (hmac_result[offset + 1] & 0xff) << 16
            | (hmac_result[offset + 2] & 0xff) << 8
            | (hmac_result[offset + 3] & 0xff);

    return bin_code;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string) {
    int i;
    char buf[21];
    memcpy(buf, secret_hex, 20);
    buf[20] = 0;

    uint8_t sec_bytes[10];
    for (i = 0; i < 10; i++) {
        sscanf(buf + 2 * i, "%02x", &sec_bytes[i]);
    }

    uint8_t counterArray[8] = {0}; //high order bytes first
    counterArray[7] = 1;

    uint8_t result[SHA1_DIGEST_LENGTH];
    getHmac(sec_bytes, counterArray, result);
    int sbits = dynamicTruncation(result);
    int modsnum = sbits % 1000000;
    int input = atoi(HOTP_string);

    return (modsnum == input);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string) {
    int i;

    char buf[21];
    memcpy(buf, secret_hex, 20);
    buf[20] = 0;

    uint8_t sec_bytes[10];
    for (i = 0; i < 10; i++) {
        sscanf(buf + 2 * i, "%02x", &sec_bytes[i]);
    }

    time_t t = time(NULL);
    long T = t / 30;

    uint8_t result[SHA1_DIGEST_LENGTH];
    uint8_t time_bytes[8];
    for (i = 7; i >= 0; i--) {
        time_bytes[i] = T;
        T >>= 8;
    }
    getHmac(sec_bytes, time_bytes, result);
    int sbits = dynamicTruncation(result);
    int modsnum = sbits % 1000000;
    int input = atoi(TOTP_string);

    return (modsnum == input);
}

int
main(int argc, char * argv[]) {
    if (argc != 4) {
        printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
        return (-1);
    }

    char * secret_hex = argv[1];
    char * HOTP_value = argv[2];
    char * TOTP_value = argv[3];

    assert(strlen(secret_hex) == 20);
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
