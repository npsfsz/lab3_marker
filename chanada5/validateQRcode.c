#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

#define SECRET_LEN 10

static int
hexToBinary(char c) {
	// convert secret to binary
	 switch(c){
		 case '0': return 0b0000;
		 case '1': return 0b0001;
		 case '2': return 0b0010;
		 case '3': return 0b0011;
		 case '4': return 0b0100;
		 case '5': return 0b0101;
		 case '6': return 0b0110;
		 case '7': return 0b0111;
		 case '8': return 0b1000;
		 case '9': return 0b1001;
		 case 'A': return 0b1010;
		 case 'B': return 0b1011;
		 case 'C': return 0b1100;
		 case 'D': return 0b1101;
		 case 'E': return 0b1110;
		 case 'F': return 0b1111;
		 case 'a': return 0b1010;
		 case 'b': return 0b1011;
		 case 'c': return 0b1100;
		 case 'd': return 0b1101;
		 case 'e': return 0b1110;
		 case 'f': return 0b1111;
	 }
}

int
HOTP(char * secret_hex, char * OTP_string, unsigned char counter[])
{
	// create the padding for the HMAC
	uint8_t ipad = 0x36;
	uint8_t opad = 0x5C;

    // create the array to hold the key in binary
	uint8_t binary_secret[SECRET_LEN];

	// pad zeros to the right if needed
	int i, j;
	char padded_hex[21] = "";
	int length_of_secret = strlen(secret_hex);
	if (length_of_secret < 20) {
		for (i = 0; i < 20; i++) {
			padded_hex[i] = '0';
		}
		for (i = 0, j = 0; i < length_of_secret; i++, j++) {
			padded_hex[i] = secret_hex[j];
		}
        padded_hex[20] = '\0';
	} else {
		snprintf(padded_hex, 21, secret_hex);
	}

	for (i = 0; i < SECRET_LEN; i++) {
		binary_secret[i] = (hexToBinary(padded_hex[2*i]) << 4) + hexToBinary(padded_hex[2*i + 1]);
	}

//	printf("\npadded:%s", padded_hex);

	// XOR the opad and the key, and the ipad and the key
	uint8_t secret_opad[64];
	uint8_t secret_ipad[64];

	for (i = 0; i < SECRET_LEN; i++) {
		secret_ipad[i] = ipad ^ binary_secret[i];
		secret_opad[i] = opad ^ binary_secret[i];
	}
	// pad ipad/opad to the right up to 64 bytes
	memset(secret_ipad + SECRET_LEN, 0x36, 64-SECRET_LEN);
	memset(secret_opad + SECRET_LEN, 0x5C, 64-SECRET_LEN);

	// HMAC
	// hash the XOR-ed key and the counter
	uint8_t	sha[SHA1_DIGEST_LENGTH];
	SHA1_INFO ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, secret_ipad, 64);
	sha1_update(&ctx, counter, 8);
	sha1_final(&ctx, sha);

	// hash the XOR-ed key and the result from the hash above
	sha1_init(&ctx);
	sha1_update(&ctx, secret_opad, 64);
	sha1_update(&ctx, sha, 20);
	sha1_final(&ctx, sha);

	// HOTP algorithm
	uint8_t offset = sha[19] & 0xf;
//	printf("\nOffset: %d", offset);
	uint32_t dbc = ((sha[offset] & 0x7f) << 24)
			| ((sha[offset+1] & 0xff) << 16)
			| ((sha[offset+2] & 0xff) << 8)
			| (sha[offset+3] & 0xff);
//	printf("\ndbc: %d", dbc);
	uint32_t HOTP_int = dbc % 1000000;
//	printf("\nHOTP_int: %d", HOTP_int);

    // count the number of digits inside HOTP_int to make sure it has 6
    // else pad with 0s
    int count_HOTP = HOTP_int;
    int count = 0;
    while(count_HOTP){
      count_HOTP = count_HOTP/10;
      count++;
    }

    char valid_HOTP[7] = "";
    if (count < 6) { 
        // pad the beginning with zeros
        for (i = 1; i <= 6-count; i++) {
            valid_HOTP[i-1] = '0';
        }
       
        char temp[7] = "";
        sprintf(temp, "%d", HOTP_int);
        strcat(valid_HOTP, temp);
    } else {
        sprintf(valid_HOTP, "%d", HOTP_int);
    }

	
	
//	printf("\nExpected HOTP: %s", valid_HOTP);
	if (!strcmp(OTP_string, valid_HOTP)) {
		return 1;
	}

	return 0;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	// counter in this case is always 1
	unsigned char counter[8];
	memset(counter, 0, sizeof(counter));
	counter[7] = 1;
	return HOTP(secret_hex, HOTP_string, counter);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	// counter is going to be number of 30 second intervals elapsed since epoch
	unsigned char counter[8];
	unsigned long long int currTime = (long long int)time(NULL);
	unsigned int period = 30;
	unsigned long long int tc = currTime/period;

	// put into a byte array
	int i ;
	for (i = 7; i >= 0; i--) {
		counter[i] = tc & 0xff;
		tc = tc >> 8;
	}

	return HOTP(secret_hex, TOTP_string, counter);

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
