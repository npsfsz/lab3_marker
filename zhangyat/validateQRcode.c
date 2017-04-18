#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#include "lib/encoding.h"

char hex_convert(char c) {
    if (c >= '0' && c <= '9')
        return c - 48;
    else // upper case characters only
        return c - 65 + 10;
}

void get_secret_hex(char* secret_hex, char* string_hex) {
    int i;
    for (i = 0; i < strlen(string_hex); i += 2) {
        secret_hex[i / 2] = (hex_convert(string_hex[i]) << 4)
                        + hex_convert(string_hex[i+1]);
    }
    secret_hex[10] = '\0';
}

void get_code(char* hmac_str, char* secret_hex, int hotp) {
    uint8_t secret_bin[10];
    get_secret_hex(secret_bin, secret_hex);

    char secret[64] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    int i;
    for (i = 0; i != 10; ++i) {
        secret[i] = secret_bin[i];
    }

    char opad[64] = "\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c\x5c";
    char ipad[64] = "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36";

//     char* m = HOTP_string;

    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];

    char tmp[64];
    for (i = 0; i != 64; ++i)
        tmp[i] = secret[i] ^ ipad[i];
    unsigned long t = ((unsigned long)time(NULL)) / 30;
    char m[8];
    m[7] = hotp == 1 ? 1 : ((t >> 0) & 0xff); // This is the hard-coded counter value.
    m[6] = hotp == 1 ? 0 : ((t >> 8) & 0xff); // This is the hard-coded counter value.
    m[5] = hotp == 1 ? 0 : ((t >> 16) & 0xff); // This is the hard-coded counter value.
    m[4] = hotp == 1 ? 0 : ((t >> 24) & 0xff); // This is the hard-coded counter value.
    m[3] = hotp == 1 ? 0 : ((t >> 32) & 0xff); // This is the hard-coded counter value.
    m[2] = hotp == 1 ? 0 : ((t >> 40) & 0xff); // This is the hard-coded counter value.
    m[1] = hotp == 1 ? 0 : ((t >> 48) & 0xff); // This is the hard-coded counter value.
    m[0] = hotp == 1 ? 0 : ((t >> 56) & 0xff); // This is the hard-coded counter value.

    sha1_init(&ctx);
    sha1_update(&ctx, tmp, 64);
    sha1_update(&ctx, m, 8);
    sha1_final(&ctx, sha);

    char tmp2[64];
    for (i = 0; i != 64; ++i)
        tmp2[i] = secret[i] ^ opad[i];

    sha1_init(&ctx);
    sha1_update(&ctx, tmp2, 64);
    sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, sha);

    int offset = sha[19] & 0xf;
    int bin_code = (sha[offset] & 0x7f) << 24
                 | (sha[offset + 1] & 0xff) << 16
                 | (sha[offset + 2] & 0xff) << 8
                 | (sha[offset + 3] & 0xff);
    int hmac = bin_code % (int)(1e6);
    printf("hmac: %d\n", hmac);

    for (i = 0; i != 6; ++i) {
        hmac_str[5 - i] = hmac % 10 + 48;
        hmac /= 10;
    }
    hmac_str[6] = '\0';

    printf("1e6: %d\n", (int)(1e6));
    printf("bin_code: %d\n", bin_code);
    printf("hmac_str: %s\n", hmac_str);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    char hmac_str[7];
    get_code(hmac_str, secret_hex, 1);
	return strcmp(hmac_str, HOTP_string) == 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    char hmac_str[7];
    get_code(hmac_str, secret_hex, 0);
	return strcmp(hmac_str, TOTP_string) == 0;
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
