#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

/* HMAC = H[(K ^ opad) || H((K ^ ipad) || M)]
where K is the key, padded with 0's on right side to N bits
opad = 0x3636... repeated to N bits
ipad = 0x5c5c... repeated to N bits
M is the message.


----------------------HOTP----------------------------
K is the key, C is the counter (= 1 in our case.)
Step 1: Generate an HMAC-SHA-1 value
Let HS = HMAC-SHA-1(K,C), where HS is a 20-byte string

Step 2: Generate a 4-byte string (Dynamic Truncation)
Let Sbits = DT(HS)

Step 3: Compute an HOTP value
Let Snum = StToNum(Sbits)

Return D = Snum mod 10^Digit, where Digit = 6 in our case.

DT(String) // String = String[0]...String[19]

Let OffsetBits be the low-order 4 bits of String[19]
Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
Let P = String[OffSet]...String[OffSet+3]
Return the Last 31 bits of P

----------------------TOTP----------------------------
TOTP = HOTP(K, T), where K is the key and T - (current unix time - 1)
 */

int DT(uint8_t *hmac) {
	int offset = hmac[19] & 0xf;
	int bin_code = (hmac[offset] & 0x7f) << 24
		| (hmac[offset] & 0xff) << 16
		| (hmac[offset] & 0xff) << 8
		| (hmac[offset] & 0xff);

	return bin_code;
}

/* value refers to either the count or the time. */
int HMAC(char *secret_hex, int value) {

	/* Convert to byte array in order to calculate sha1. */
	char *pos = secret_hex;
	uint8_t data[10];
	int count;

	for (count=0; count<sizeof(data)/sizeof(data[0]); count++) {
		sscanf(pos, "%2hhx", &data[count]);
		pos += 2;
	}

	uint8_t opad[64];
	uint8_t ipad[64];

	memset(opad, 0, 64);
	memset(ipad, 0, 64);

	int i;
	for (i=0; i<64; i++) {
		if (i<10) {
			opad[i] = 0x36 ^ data[i];
			ipad[i] = 0x5c ^ data[i];
		}
		else {
			opad[i] = 0x36;
			ipad[i] = 0x5c;
		}
	}

	uint8_t *val_array = (uint8_t *)&value;

	/* Compute the inner hash */
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, ipad, 64);
	sha1_update(&ctx, val_array, 8);
	sha1_final(&ctx, sha);

	/* Computer the outer hash now. */
	SHA1_INFO ctx2;
	uint8_t sha2[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx2);
	sha1_update(&ctx2, opad, 64);
	sha1_update(&ctx, sha, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, sha2);

	int sbits = DT(sha2);

	// printf("SHA1: %s\n", sha);
	// printf("\n");
	int ret = (int) sbits % (int) (1000000);
	return ret;

}
static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	int sec_hotp = HMAC(secret_hex, 1);
	int hotp = atoi(HOTP_string);
	if (sec_hotp == hotp) {
		return (1);
	}
	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int t = (int)time(NULL);
	int sec_totp = HMAC(secret_hex, t);
	int totp = atoi(TOTP_string);

	if(sec_totp == totp) {
		return (1);
	}
	return (0);
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

	char padded_secret[21];
	memset(padded_secret, '0', 20);

	/* Add padding if the secret is not 20 bytes. */
	if (strlen(secret_hex) < 20) {
		int i;
		for (i=0;i<strlen(secret_hex);i++) {
			padded_secret[i] = secret_hex[i];
		}
	}

	else {
		strncpy(padded_secret, secret_hex, 20);
	}

	 printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
	 	secret_hex,
	 	HOTP_value,
	 	validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
	 	TOTP_value,
	 	validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");
	//validateHOTP(padded_secret, HOTP_value);

	return(0);
}
