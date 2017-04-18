#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

#define HEX_LEN 20
#define HEX_BYTE_LEN (HEX_LEN / 2)
#define OTP_LEN 6

static int validate_otp_common(char *secret_hex, unsigned long data_init, char *OTP_string)
{
    // Initialize data
    unsigned char data[sizeof(data_init)];
    int i;
    for (i = sizeof(data_init) - 1; i >= 0; --i) {
        data[i] = (unsigned char) (data_init & 0xff);
        data_init >>= 8;
    }

    // Get secret hex in bytes
    const int secret_bytes_len = strlen(secret_hex) / 2;
    unsigned char *secret_bytes = malloc(secret_bytes_len * sizeof(unsigned char));
	for (i = 0; i < secret_bytes_len; ++i) {
        sscanf(&secret_hex[i * 2], "%02x", &secret_bytes[i]);
    }

    // HMAC
    unsigned char ipad[65], opad[65];
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memcpy(ipad, secret_bytes, secret_bytes_len);
    memcpy(opad, secret_bytes, secret_bytes_len);

    for (i = 0; i < 64; ++i) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    SHA1_INFO ctx;

    unsigned char inner_hmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, data, sizeof(data));
    sha1_final(&ctx, inner_hmac);

    unsigned char outer_hmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, inner_hmac, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, outer_hmac);

    int offset = outer_hmac[SHA1_DIGEST_LENGTH - 1] & 0x0f;
    unsigned long binary = ((outer_hmac[offset] & 0x7f) << 24)
        | ((outer_hmac[offset + 1] & 0xff) << 16)
        | ((outer_hmac[offset + 2] & 0xff) << 8)
        | ( outer_hmac[offset + 3] & 0xff);

    char calculated_otp_str[OTP_LEN + 1];
    sprintf(calculated_otp_str, "%06ld", binary % 1000000);
    return !strcmp(OTP_string, calculated_otp_str);
}

static int validateHOTP(char *secret_hex, char *HOTP_string)
{
    return validate_otp_common(secret_hex, 1, HOTP_string);
}

static int validateTOTP(char *secret_hex, char *TOTP_string)
{
    return validate_otp_common(secret_hex, (unsigned long)(time(NULL) / 30),
							   TOTP_string);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
        return -1;
    }

    char *secret_hex = argv[1];
    char *HOTP_value = argv[2];
    char *TOTP_value = argv[3];

    assert(strlen(secret_hex) <= HEX_LEN);
    assert(strlen(HOTP_value) == OTP_LEN);
    assert(strlen(TOTP_value) == OTP_LEN);

    printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		   secret_hex,
		   HOTP_value,
		   validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		   TOTP_value,
		   validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

    return 0;
}
