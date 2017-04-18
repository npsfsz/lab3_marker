#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

#define LOWB4(p) ((p >> 0) & 0xF)
#define LOWB7(p) ((p >> 0) & 0x7F)
#define BOFF0(p) ((p >> 0) & 0xFF)
#define BOFF1(p) ((p >> 8) & 0xFF)
#define BOFF2(p) ((p >> 16) & 0xFF)
#define BOFF3(p) ((p >> 24) & 0xFF)

#define XOR36(p) (p ^= 0x36)
#define XOR5c(p) (p ^= 0x5c)

#define MIL 1000000
#define OTP(h) ((LOWB7(h[LOWB4(h[19])]) << 24 | BOFF0(h[LOWB4(h[19]) + 1]) << 16 | BOFF0(h[LOWB4(h[19]) + 2]) << 8 | BOFF0(h[LOWB4(h[19]) + 3])) % MIL)

static int validateHOTP(char * secret_hex, char * HOTP_string) {
    unsigned i;
    unsigned t_len = 8;
    unsigned pad_len = 64;
    unsigned data_len = 10;
    
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    uint8_t data[data_len];
    
    uint8_t t[t_len];
    uint8_t ipad[pad_len];
    uint8_t opad[pad_len];

    char conv[2];
    char* pEnd;
    
    for (i = 0; i < t_len-1; i++)
        t[i] = 0;
    t[i] = 1;

    for (i = 0; i < data_len; i++) {
        conv[0] = secret_hex[2 * i];
        conv[1] = secret_hex[2 * i + 1];
        data[i] = BOFF0(strtoul(conv, &pEnd, 16));
    }

    bzero(ipad, pad_len);
    bzero(opad, pad_len);
    bcopy(data, ipad, data_len);
    bcopy(data, opad, data_len);

    for (i = 0; i < pad_len; i++) {
        ipad[i] = XOR36(ipad[i]);
        opad[i] = XOR5c(opad[i]);
    }

    sha1_init(&ctx);
    sha1_update(&ctx, ipad, pad_len);
    sha1_update(&ctx, t, t_len);
    sha1_final(&ctx, sha);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, pad_len);
    sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, sha);
    
    return (atoi(HOTP_string) == OTP(sha));
}

static int validateTOTP(char * secret_hex, char * TOTP_string) {
    unsigned i;
    unsigned t_len = 8;
    unsigned pad_len = 64;
    unsigned data_len = 10;
    unsigned time_ = time(NULL) / 30;
    
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    uint8_t data[data_len];

    uint8_t t[t_len];
    uint8_t ipad[pad_len];
    uint8_t opad[pad_len];

    char conv[2];
    char* pEnd;
    
    for (i = 0; i < t_len; i++) {
        t[7 - i] = BOFF0(time_);
        time_ >>= t_len;
    }

    for (i = 0; i < data_len; i++) {
        conv[0] = secret_hex[2 * i];
        conv[1] = secret_hex[2 * i + 1];
        data[i] = BOFF0(strtoul(conv, &pEnd, 16));
    }

    bzero(ipad, pad_len);
    bzero(opad, pad_len);
    bcopy(data, ipad, data_len);
    bcopy(data, opad, data_len);

    for (i = 0; i < pad_len; i++) {
        ipad[i] = XOR36(ipad[i]);
        opad[i] = XOR5c(opad[i]);
    }

    sha1_init(&ctx);
    sha1_update(&ctx, ipad, pad_len);
    sha1_update(&ctx, t, t_len);
    sha1_final(&ctx, sha);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, pad_len);
    sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, sha);
    
    return (atoi(TOTP_string) == OTP(sha));
}

int main(int argc, char * argv[]) {
    if (argc != 4) {
        printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
        return (-1);
    }

    char * secret_hex = argv[1];
    char * HOTP_value = argv[2];
    char * TOTP_value = argv[3];

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
