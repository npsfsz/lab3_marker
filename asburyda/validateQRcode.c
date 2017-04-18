#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

    int dynamicTruncation(uint8_t* hmac){
    int offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0x0f;
    long binary = ((hmac[offset] & 0x7f) << 24)
            | ((hmac[offset + 1] & 0xff) << 16)
            | ((hmac[offset + 2] & 0xff) << 8)
            | ( hmac[offset + 3] & 0xff); 
    return binary;
}

int validateOTP(char* secret_hex, uint8_t* data,char* OTP_string){
    uint8_t byteArray[10];
    uint8_t o_key_pad[64];
    uint8_t i_key_pad[64];
    unsigned i;
    SHA1_INFO ctx;
    //convert to byte array
    for(i=0;i<10;i++){
        sscanf(secret_hex,"%2hhx",&byteArray[i]);
        secret_hex +=2;
    }
    //form of the key pads
    for(i=0;i<64;i++){
        if(i<10){
            o_key_pad[i] = byteArray[i];
            i_key_pad[i] = byteArray[i];
        } else {
            o_key_pad[i] = 0x00;
            i_key_pad[i] = 0x00;
        }
    }
    for(i=0;i<64;i++){
        o_key_pad[i]^=0x5c;
        i_key_pad[i]^=0x36;
    }
    //compute sha1 inner hash hash
    uint8_t inner[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx,i_key_pad,64);
    sha1_update(&ctx,data,8);
    sha1_final(&ctx,inner);
    
    //compute hmac with sha1
    uint8_t hmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx,o_key_pad,64);
    sha1_update(&ctx,inner,SHA1_DIGEST_LENGTH);
    sha1_final(&ctx,hmac);
    
    //it says to do this in the rfc documents
    int binary = dynamicTruncation(hmac);
    int mod_otp = binary % 1000000;

    int OTP_stringn = atoi(OTP_string);
    if(OTP_stringn == mod_otp){
        return 1;
    } else {
        return 0;
    }
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    int i;
    long counter = 1;
    uint8_t text[sizeof(counter)];
    for( i = sizeof(text)-1; i >= 0 ; i--){
        text[i] = (char)(counter & 0xff);
        counter >>= 8;
    }
    return validateOTP(secret_hex,text,HOTP_string);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    uint8_t time_bytes[8];
    int i;
     time_t t = time(NULL);
    long T = t/30;
    for (i = 7; i >= 0; i--) {
            time_bytes[i] = T;
            T >>= 8;
    }
    return validateOTP(secret_hex,time_bytes,TOTP_string);
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