#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>

#include "lib/sha1.h"

#define SHA1_DIGEST_LENGTH 20
#define DIGIT 6

/*
 * the HMAC_SHA1 transform looks like:
 *
 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
 *
 * where K is an n byte key
 * ipad is the byte 0x36 repeated 64 times
 * opad is the byte 0x5c repeated 64 times
 * and text is the data being protected
 */
void HMAC_SHA1(char * hex_key, unsigned char * text, int text_len, uint8_t * sha) {
    SHA1_INFO ctx;
    unsigned char k_ipad[65]; // inner padding
    unsigned char k_opad[65]; // outer padding

    // make sure key is even number
    char secret_hex[40];
    if (strlen(hex_key) % 2 != 0) {
        strcpy(secret_hex, "0");
        strcat(secret_hex, hex_key);
    } else {
        strcpy(secret_hex, hex_key);
    }

    bzero(k_ipad, sizeof k_ipad);
    bzero(k_opad, sizeof k_opad);

    /* Start out by storing key in pads.
     * During the process convert to base256
     * and copy into the pads, i.e. one byte
     * per array element.
     */
    int len = strlen(secret_hex) / 2;
    char * pos = secret_hex;
    int i;
    for(i = 0; i < len; i++) {
         sscanf(pos, "%2hhx", &k_ipad[i]);
         k_opad[i] = k_ipad[i];
         pos += 2;
    }

    /* XOR key with ipad and opad values */
    for (i=0; i<64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /*
    * perform inner sha1
    */
    sha1_init(&ctx); /* init context for 1st pass */
    sha1_update(&ctx, k_ipad, 64); /* start with inner pad */
    sha1_update(&ctx, text, text_len); /* then text of datagram */
    sha1_final(&ctx, sha); /* finish up 1st pass */

    /*
    * perform outer sha1
    */
    sha1_init(&ctx); /* init context for 2nd pass */
    sha1_update(&ctx, k_opad, 64); /* start with outer pad */
    sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH); /* result of 1st hash */
    sha1_final(&ctx, sha); /* finish up 2nd pass */
}

int truncate(uint8_t * hmac_result) {
    int offset = hmac_result[19] & 0xf;// 0 <= offset <= 15
    int bin_code = (hmac_result[offset] & 0x7f) << 24
        | (hmac_result[offset+1] & 0xff) << 16
        | (hmac_result[offset+2] & 0xff) << 8
        | (hmac_result[offset+3] & 0xff);
    return (bin_code % 1000000); // bin_code % 10^DIGIT
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    uint8_t sha[SHA1_DIGEST_LENGTH + 1];
    uint8_t counter[] = {0,0,0,0,0,0,0,1}; // 8 byte counter according to spec
    HMAC_SHA1(secret_hex, counter, 8, sha);

    char gen_HOTP_string[7];
    sprintf(gen_HOTP_string, "%d", truncate(sha));

    return (strcmp(gen_HOTP_string, HOTP_string) == 0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    uint8_t sha[SHA1_DIGEST_LENGTH + 1];
    unsigned long X = 30, T0 = 0, T;
    T = ((unsigned long)time(NULL) - T0) / X;
    uint8_t counter[] = {
        (T >> 56) & 0xff,
        (T >> 48) & 0xff,
        (T >> 40) & 0xff,
        (T >> 32) & 0xff,
        (T >> 24) & 0xff,
        (T >> 16) & 0xff,
        (T >> 8) & 0xff,
        T & 0xff
    };
    HMAC_SHA1(secret_hex, counter, 8, sha);

    char gen_TOTP_string[7];
    sprintf(gen_TOTP_string, "%d", truncate(sha));

    return (strcmp(gen_TOTP_string, TOTP_string) == 0);
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
