#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"
#define SECRET_HEX_LEN 20
#define NUM_SECRET_BYTES 10
#define MAX_URI_LEN 300
//Assume hash block size = n bits (e.g., 512 bits for SHA1)

#define SHA1_LEN 512

typedef union uint32_4x8_t
{
    uint32_t u_int32;
    uint8_t char4[4];
} uint32_4x8_t;    


void hmac_sha1(uint8_t *key, uint64_t counter, uint8_t *hmac, int hmac_len)
{
    //create SHA struct
    SHA1_INFO first;
    SHA1_INFO second;
    
    uint8_t sha[SHA1_DIGEST_LENGTH];
    uint8_t o_key_pad[SHA1_BLOCKSIZE];
    uint8_t i_key_pad[SHA1_BLOCKSIZE];

    int i;

    memset(i_key_pad, 0x36, SHA1_BLOCKSIZE);
    memset(o_key_pad, 0x5c, SHA1_BLOCKSIZE);
    for(i =0; i < NUM_SECRET_BYTES; i++)
    {
        i_key_pad[i] = i_key_pad[i] ^ key[i];
        o_key_pad[i] = o_key_pad[i] ^ key[i];
    }



    sha1_init(&first);
    sha1_update(&first, i_key_pad, SHA1_BLOCKSIZE);
    sha1_update(&first, (uint8_t*)&counter, 8);    
    sha1_final(&first, sha);

    sha1_init(&second);
    sha1_update(&second, o_key_pad, SHA1_BLOCKSIZE);
    sha1_update(&second, sha, SHA1_DIGEST_LENGTH);   
    sha1_final(&second, sha);

    memcpy(hmac,sha,hmac_len);

    return;
}

uint32_t dynamicTruncation(uint8_t* sha_result)
{
    //DT(String) // String = String[0]...String[19]

// Let OffsetBits be the low-order 4 bits of String[19]
// Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
    uint32_t offset = sha_result[19] & 0xf ;

// Let P = String[OffSet]...String[OffSet+3]
    uint32_t bin_code = (sha_result[offset] & 0x7f) << 24
    | (sha_result[offset+1] & 0xff) << 16
    | (sha_result[offset+2] & 0xff) << 8
    | (sha_result[offset+3] & 0xff) ;

//Return the Last 31 bits of P
    return bin_code;
}


static int
validateHOTP(char *secret_hex, char *HOTP_string)
{

    const uint64_t counter = 1;
    uint8_t hs[SHA1_DIGEST_LENGTH]; // hashed result
    uint32_4x8_t Sbits;
    int HOTP = atoi(HOTP_string);
    int calculatedHOTP;

    char padded_secret[SECRET_HEX_LEN];
    int len = strlen(secret_hex);
    assert(len <= SECRET_HEX_LEN);

    int i = 0;
    for (i = 0; i < len; i++)
    {
        padded_secret[i] = secret_hex[i];
    }

    //if its less than 20 than pad rest with zeroes
    if (len <= SECRET_HEX_LEN)
    {
        int padding_len = SECRET_HEX_LEN - len;

        for (i = len; i < SECRET_HEX_LEN; i++)
        {
            padded_secret[i] = '0';
        }
    }
    //convert hexidecimal representation to a byte array 20 hex digits/2= 10 bytes
    uint8_t byte_arr[NUM_SECRET_BYTES];
    for (i = 0; i < NUM_SECRET_BYTES; i++)
    {
        sscanf(&padded_secret[2 * i], "%02x", &byte_arr[i]);
    }

    uint64_t reverseCounter =   (counter & (0xff)) << 56
                            |   (counter & (0xff00)) << 40
                            |   (counter & (0xff0000)) << 24
                            |   (counter & (0xff000000)) << 8
                            |   (counter & (0xff00000000)) << 0
                            |   (counter & (0xff0000000000 )) >> 8
                            |   (counter & (0xff000000000000)) >> 16
                            |   (counter & (0xff00000000000000)) >> 24;

    hmac_sha1(byte_arr, reverseCounter, hs, SHA1_DIGEST_LENGTH);
    Sbits.u_int32 = dynamicTruncation(hs);
    calculatedHOTP = (int) ((Sbits.u_int32) % 1000000);

    return HOTP == calculatedHOTP;
}

static int
validateTOTP(char *secret_hex, char *TOTP_string)
{
    
    uint8_t hs[SHA1_DIGEST_LENGTH]; // hashed result
    uint32_4x8_t Sbits;
    int HOTP = atoi(TOTP_string);
    int calculatedHOTP;
    uint64_t counter = (uint64_t)time(NULL) / 30;

    char padded_secret[SECRET_HEX_LEN];
    int len = strlen(secret_hex);
    assert(len <= SECRET_HEX_LEN);

    int i = 0;
    for (i = 0; i < len; i++)
    {
        padded_secret[i] = secret_hex[i];
    }

    //if its less than 20 than pad rest with zeroes
    if (len <= SECRET_HEX_LEN)
    {
        int padding_len = SECRET_HEX_LEN - len;

        for (i = len; i < SECRET_HEX_LEN; i++)
        {
            padded_secret[i] = '0';
        }
    }
        //convert hexidecimal representation to a byte array 20 hex digits/2= 10 bytes

    uint8_t byte_arr[NUM_SECRET_BYTES];
    for (i = 0; i < NUM_SECRET_BYTES; i++)
    {
        sscanf(&padded_secret[2 * i], "%02x", &byte_arr[i]);
    }

    uint64_t reverseCounter =   (counter & (0xff)) << 56
                            |   (counter & (0xff00)) << 40
                            |   (counter & (0xff0000)) << 24
                            |   (counter & (0xff000000)) << 8
                            |   (counter & (0xff00000000)) << 0
                            |   (counter & (0xff0000000000 )) >> 8
                            |   (counter & (0xff000000000000)) >> 16
                            |   (counter & (0xff00000000000000)) >> 24;

    hmac_sha1(byte_arr, reverseCounter, hs, SHA1_DIGEST_LENGTH);
    Sbits.u_int32 = dynamicTruncation(hs);
    calculatedHOTP = (int) ((Sbits.u_int32) % 1000000);

    return HOTP == calculatedHOTP;
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
        return (-1);
    }

    char *secret_hex = argv[1];
    char *HOTP_value = argv[2];
    char *TOTP_value = argv[3];

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
