#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>

#include "lib/sha1.h"

#define BLOCK_SIZE 64
#define SECRET_LEN 20

char * hex_convert(char *input) {
    int len=strlen(input) ;
    int i ;

    for (i=0; i<len; i++) {
        if (input[i] >= '0' && input[i] <= '9')
            input[i] = input[i] - '0' ;
        else if (input[i] >= 'A' && input[i] <= 'Z')
            input[i] = input[i] - 'A' + 10;
        else if (input[i] >= 'a' && input[i] <= 'z')
            input[i] = input[i] - 'a' + 10 ;
        else
            input[i] = '0' ;
        if (i % 2 == 0 )
                input[i] = input[i]<< 4 ;
        else {
                input[i] = input[i] | input[i-1] ;
                input[(i-1)/2] = input[i] ;
        }
    }

    input[SECRET_LEN/2] = '\0' ;
    return input ;
printf("%d:%2x\n", (i-1)/2, input[(i-1)/2]) ;
}

void calculateHMAC(uint8_t *secret_key, uint8_t *text, uint8_t *shaouter ) {
    int i ;
    uint8_t o_key_pad[BLOCK_SIZE] ;
    uint8_t i_key_pad[BLOCK_SIZE] ;
  

    for(i=0; i<BLOCK_SIZE; i++) {
        if (i<SECRET_LEN/2) {
            o_key_pad[i] = 0x5c ^ secret_key[i] ;
            i_key_pad[i] = 0x36 ^ secret_key[i] ;
        }
        else {
           o_key_pad[i] = 0x5c ^ 0x00 ;
           i_key_pad[i] = 0x36 ^ 0x00 ;
        }
   }

    SHA1_INFO ctx;
    uint8_t shainner[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_update(&ctx, i_key_pad, BLOCK_SIZE);
    sha1_update(&ctx, text,8);
    sha1_final(&ctx, shainner);

    SHA1_INFO ctx2;
    sha1_init(&ctx2);
    sha1_update(&ctx2, o_key_pad, BLOCK_SIZE);
    sha1_update(&ctx2, shainner,SHA1_DIGEST_LENGTH);
    sha1_final(&ctx2, shaouter);

    return ;
}

int DynamicTruncation(uint8_t *hmac_result){
          int offset   =  hmac_result[19] & 0xf;
      int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

        return bin_code;

}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    uint8_t shaouter[SHA1_DIGEST_LENGTH];

    // set counter to 1, and put the value into a binary array
    uint8_t counter[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01} ;

    // calculate HMAC value
    calculateHMAC((uint8_t *)secret_hex, (uint8_t *)counter, (uint8_t *)shaouter);

    // calculate HOTP value
    int sbits = DynamicTruncation(shaouter);
    int modsnum = (int)sbits % (int)(pow(10,6));

    // compare with user provided HOTP value
    int HOTP_stringvalue = atoi(HOTP_string);

    // if equal, return 1
    if (modsnum == HOTP_stringvalue)
        return 1;
    else
        return 0;
    
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    int i ;
    uint8_t shaouter[SHA1_DIGEST_LENGTH];

    // get current calendar time
    time_t t = time(NULL);

    // because the password expire period is 30 second
    // calculate current sequence number of period
    long period = t/30;

    // put the value of period into a binary array
    uint8_t data_of_time[8];
    for (i = 7; i >= 0; i--) {
            data_of_time[i] = period;
            period >>= 8;
    }

    // calculate HMAC value
    calculateHMAC(secret_hex, data_of_time, shaouter);

    // calculate TOTP value
    int sbits = DynamicTruncation(shaouter);
    int modsnum = (int)sbits % (int)(pow(10,6));

    // compare with user provided TOTP value
    int TOTP_stringvalue = atoi(TOTP_string);
    if (modsnum == TOTP_stringvalue)
        return 1;
    else
        return 0;

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

        char padded_secret_str[SECRET_LEN+1], *secret_strptr ;

        // if secrete key is less then 20 bytes long, pad '0' at the beginning
	int i;
        for (i=0; i<SECRET_LEN; i++)
            padded_secret_str[i] = '0' ;
        padded_secret_str[SECRET_LEN]='\0' ;
        strncpy(&padded_secret_str[SECRET_LEN-strlen(secret_hex)], secret_hex, strlen(secret_hex)) ;

        // convert the string of padded secret key to hex value
        secret_strptr = padded_secret_str ;
        secret_strptr = hex_convert(secret_strptr) ;

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_strptr, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_strptr, TOTP_value) ? "valid" : "invalid");

	return(0);
}
