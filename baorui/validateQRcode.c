#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#include "malloc.h"
#include <time.h>

#define SECRET_KEY_SIZE 80
#define SHA_DIGEST_LENGTH 160
#define SECRET_SIZE_IN_BIT 80
#define SECRET_SIZE_IN_HEX 20
#define SECRET_SIZE_IN_BYTE 10
#define SECRET_SIZE_IN_BASE32 16
#define PADDING_BLOCK_SZIE 64


/* character to integer */
int char_to_int(char c) {
    int result = 0;  // so the unexpected char will have value of 0
    if (c >= '0' && c <= '9')
        result = c - '0';
    else if (c >= 'A' && c <= 'F')
        result = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
        result = c - 'a' + 10;
    
    return result;
}

uint8_t* hexToByte(char* secret_hex){


    int secret_hex_complete[SECRET_SIZE_IN_HEX + 1];
    	secret_hex_complete[SECRET_SIZE_IN_HEX] = '\0';
   	 
    	int secret_input_len = strlen(secret_hex);
    	int i = 0;
    	for (; i < secret_input_len; i++){
        	secret_hex_complete[i] = secret_hex[i];
    	}
 
   	 
    	if (secret_input_len < SECRET_SIZE_IN_HEX){
        	for (i = secret_input_len; i < SECRET_SIZE_IN_HEX; i++){
            	secret_hex_complete[i] = '\0';
        	}  
    	}
   	 
   	 
    	// convert hex to byte
    	uint8_t* secret_in_byte = (uint8_t *)malloc(sizeof(uint8_t)*(SECRET_SIZE_IN_BYTE + 1));
    	secret_in_byte[SECRET_SIZE_IN_BYTE] = '\0';
   	 
    	for (i = 0; i < SECRET_SIZE_IN_BYTE; i++){
        	char left_hex = secret_hex_complete[i * 2];
        	char right_hex = secret_hex_complete[i * 2 + 1];
       	 
        	secret_in_byte[i] = char_to_int(left_hex) * 16 + char_to_int(right_hex);
    	}
   	 
    	return secret_in_byte;
    
}



/* truncate HMAC value to 6 digit HOTP/TOTP values */
int truncate(uint8_t hmac_result[SHA1_BLOCKSIZE]) {
    int offset = hmac_result[19] & 0xf;
    int bin_code = (hmac_result[offset] & 0x7f) << 24
            | (hmac_result[offset + 1] & 0xff) << 16
            | (hmac_result[offset + 2] & 0xff) << 8
            | (hmac_result[offset + 3] & 0xff);

    return bin_code % 1000000;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string) {
    // create 8 byte counter
    uint8_t counter[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    // pad with zero at the end if the size smaller than 20
    int secret_hex_complete[SECRET_SIZE_IN_HEX + 1];
    secret_hex_complete[SECRET_SIZE_IN_HEX] = '\0';

    int secret_input_len = strlen(secret_hex);
    int i = 0;
    for (; i < secret_input_len; i++) {
        secret_hex_complete[i] = secret_hex[i];
    }

    if (secret_input_len < SECRET_SIZE_IN_HEX) {
        for (i = secret_input_len; i < SECRET_SIZE_IN_HEX; i++) {
            secret_hex_complete[i] = '\0';
        }
    }

    // convert secret in hex to secret in bytes
    uint8_t secret_in_byte[SECRET_SIZE_IN_BYTE + 1];
    secret_in_byte[SECRET_SIZE_IN_BYTE] = '\0';

    for (i = 0; i < SECRET_SIZE_IN_BYTE; i++) {
        char left_hex = secret_hex_complete[i * 2];
        char right_hex = secret_hex_complete[i * 2 + 1];

        secret_in_byte[i] = char_to_int(left_hex) * 16 + char_to_int(right_hex);
    }

    /* prepare inner pad and outer pad */
    uint8_t ipad[PADDING_BLOCK_SZIE + 1];
    uint8_t opad[PADDING_BLOCK_SZIE + 1];
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memcpy(ipad, secret_in_byte, SECRET_SIZE_IN_BYTE);
    memcpy(opad, secret_in_byte, SECRET_SIZE_IN_BYTE);
    
    for (i = 0; i < PADDING_BLOCK_SZIE; i++){
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }
    
    /* compute hmac */
    SHA1_INFO ctx;
    uint8_t inner_hmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, PADDING_BLOCK_SZIE);
    sha1_update(&ctx, counter, sizeof(counter));
    sha1_final(&ctx, inner_hmac);
    
    uint8_t complete_hmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, inner_hmac, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, complete_hmac);
    
    /* truncate HMAC value to 6 digit HOTP values */
    int HOTP_digit_result = truncate(complete_hmac);

    /* convert HOTP_digit to string and check if the input string matches HOTP_digit or not */
    char HOTP_str_result[7];
    sprintf(HOTP_str_result, "%ld", HOTP_digit_result);
    while (strlen(HOTP_str_result) < 6){
        char HOTP_str_temp[7] = "0";
        strcat(HOTP_str_temp, HOTP_str_result);
        strcpy(HOTP_str_result, HOTP_str_temp);
    }

    return (strcmp(HOTP_string, HOTP_str_result) == 0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{    
    uint8_t opadResult= 0x5c;
    uint8_t ipadResult =0x36;

    time_t actualTime = time(NULL);
    int sec = ((int)actualTime -0)/30;
    
    uint8_t message[8];
  //uint8_t mes = (uint8_t)sec; 
    int i =0;
    for(i=0; i<8; i++){
		message[i]=0;
    }
    message[7] =sec&0x0ff;
    message[6] =(sec>>8)&0x0ff;
    message[5] =(sec>>16)&0x0ff;
    message[4] =(sec>>24)&0x0ff;
    



    //does the initalization
    uint8_t *hash = (uint8_t *)malloc(sizeof(uint8_t)*(SHA1_DIGEST_LENGTH));
    memset(hash, 0,sizeof(hash));
    char* result = NULL;
    // Using the counter
    // First 8 bytes are for the movingFactor
    // Compliant with base RFC 4226 (HOTP)

    // Get the HEX in a Byte[]
    //uint8_t* message = hexToByte(timeRes ult);
    
    int secret_hex_complete[SECRET_SIZE_IN_HEX + 1];
    secret_hex_complete[SECRET_SIZE_IN_HEX] = '\0';

    int secret_input_len = strlen(secret_hex);
    i = 0;
    for (; i < secret_input_len; i++) {
        secret_hex_complete[i] = secret_hex[i];
    }

    if (secret_input_len < SECRET_SIZE_IN_HEX) {
        for (i = secret_input_len; i < SECRET_SIZE_IN_HEX; i++) {
            secret_hex_complete[i] = '\0';
        }
    }

    // convert secret in hex to secret in bytes
    uint8_t k[SECRET_SIZE_IN_BYTE + 1];
    k[SECRET_SIZE_IN_BYTE] = '\0';

    for (i = 0; i < SECRET_SIZE_IN_BYTE; i++) {
        char left_hex = secret_hex_complete[i * 2];
        char right_hex = secret_hex_complete[i * 2 + 1];

        k[i] = char_to_int(left_hex) * 16 + char_to_int(right_hex);
    }

    
    
    // create two sha functions
    SHA1_INFO ctx1, ctx2;
    uint8_t sha2[20];
    sha1_init(&ctx1);
    sha1_init(&ctx2);

    
    // here we need to have the form
    // HMAC = H[(K XOR opad) || H((K XOR IPAD) || M)]
    uint8_t K_x_or_Ipad_padded[PADDING_BLOCK_SZIE];
    uint8_t K_x_or_Opad_padded[PADDING_BLOCK_SZIE];

    // does initialization
    memset(K_x_or_Ipad_padded, 0, sizeof(K_x_or_Ipad_padded));
    memset(K_x_or_Opad_padded, 0, sizeof(K_x_or_Opad_padded));
    memcpy(K_x_or_Ipad_padded, k, SECRET_SIZE_IN_BYTE);
    memcpy(K_x_or_Opad_padded, k, SECRET_SIZE_IN_BYTE);
    
    int counter =0;
    //K XOR IPAD
    for(; counter < PADDING_BLOCK_SZIE;counter++){
   	 K_x_or_Ipad_padded[counter] ^=ipadResult;
   	 
    }
    // we append the k xor IPAD into sha1
    sha1_update(&ctx2,K_x_or_Ipad_padded, PADDING_BLOCK_SZIE);
    
    // adding this to || with message
    sha1_update(&ctx2,message,8);

    // create the first part of the hash
    sha1_final(&ctx2,sha2);
    
    // we do the same thing for the same part to xor
    for(counter=0; counter < PADDING_BLOCK_SZIE; counter++){
   	 K_x_or_Opad_padded[counter] ^= opadResult;

    }
    // do the last steps to apppend the whole hmac together
    sha1_update(&ctx1,K_x_or_Opad_padded, PADDING_BLOCK_SZIE);
    sha1_update(&ctx1,sha2,(SHA1_DIGEST_LENGTH));
    sha1_final(&ctx1,hash);


    

    // put selected bytes into result int
    int offset = hash[19] & 0xf;
    int binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
    int otp = binary % 1000000;

    // we scan the rest of the otp into a char*
    char computed_totp[7];
    sprintf(computed_totp,"%d",otp);
    //printf("the test message is %s",computed_totp);
    
    while (strlen(computed_totp) < 6){
        char TOTP_str_temp[7] = "0";
        strcat(TOTP_str_temp, computed_totp);
        strcpy(computed_totp, TOTP_str_temp);
    }

    if(strcmp(TOTP_string,computed_totp)!=0){
   	 return (0);
    }
    else
   	 return (1);
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
