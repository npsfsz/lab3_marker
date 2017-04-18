#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include "lib/sha1.h"
#include <time.h>

int truncate(uint8_t hsh[],int n)
{   
    int offset;
    // Make len = 20 as the output 
    // for the final sha places a 20 byte value
    // into digest
    int len = 20;
    offset = hsh[len-1] & 0xf;
    
    int binvalue;
    
    binvalue = \
        (hsh[offset] & 0x7f) << 24 \
        | (hsh[offset+1] & 0xff) << 16 \
        | (hsh[offset+2] & 0xff) << 8 \
        | (hsh[offset+3] & 0xff);
    
    // The power to modulo with is 10^6 so
    // we get a 6 bit output
    return (binvalue % 1000000);
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
        // 2 contexts, one for the inner hash
        // And one for the outer hash
        SHA1_INFO context;
        SHA1_INFO context2;
        
        // An array for the IPAD to XOR with the key
        uint8_t *keyXORipad;
        // Another array for the OPAD to XOR with the key
        uint8_t *keyXORopad;

        // Convert the secret_hex to binary form
        uint8_t encoders[64];
        int i = 0;
        for (i = 0; i < strlen(secret_hex)/2; i++)
            sscanf((i*2)+secret_hex, "%2x", &encoders[i]);
        
        // Pad the rest of the binary key with 0's
        // We pad it to keep it the same length as the 
        // XOR's. May not be strictly necessary
        for (i = strlen(secret_hex)/2; i < 64; i++)
            encoders[i] = 0;
        
        // The counter is 1. So convert 1 to binary form
        // Need to store it in Big Endian form so place it
        // in counter[7]
        uint8_t counter[8];
        sscanf("1", "%2x", &counter[7]);
        
        // Pad the beginning of the message with 0's
        for (i = 0; i < 7; i++)
            counter[i] = 0;


        // The sha is of the form
        // SHA1(K XOR opad, SHA1(K XOR ipad, text))
         
        // First store 0's in the arrays
        keyXORipad = (uint8_t*)(calloc(64, sizeof(uint8_t)));
        keyXORopad = (uint8_t*)(calloc(64, sizeof(uint8_t)));
        // Store the keys in each respective XOR array
        memcpy( keyXORipad, encoders, 64);
        memcpy( keyXORopad, encoders, 64);

        // Compute the inner and outer XOR's
        for (i = 0; i < 64; i++) {
                keyXORipad[i] ^= 0x36;
                keyXORopad[i] ^= 0x5c;
        }

        // Inner SHA1
        
        // Initialize context
        sha1_init(&context); 
        // Update with the Inner Pad
        sha1_update(&context, keyXORipad, 64);
        // Update with the message counter
        sha1_update(&context, counter, 8);
        // Store the output in digest; 20 Bytes
        uint8_t digest[20];
        sha1_final(&context, digest);
        
        // Outer Hash
        
        // Initialize context 2
        sha1_init(&context2);
        // Updatew with outer pad and output of inner hash
        sha1_update(&context2, keyXORopad, 64);
        sha1_update(&context2, digest, 20);
        // Store the output of digest; 20 Bytes
        uint8_t d2[20];
        sha1_final(&context2, d2);
        
        // Truncate Output to 6 Bytes
        int value = truncate(d2, 6);
        
        // Convert Integer to String.
        char * finalResult = (char*)malloc(6);
        sprintf(finalResult,  "%d", value);
        
        // Check if provided HOTP_string is valid
        if(strcmp(finalResult, HOTP_string) == 0)
            return 1;
        else
            return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
        // 2 contexts, one for the inner hash
        // And one for the outer hash
        SHA1_INFO context;
        SHA1_INFO context2;
        
        // An array for the IPAD to XOR with the key
        uint8_t *keyXORipad;
        // Another array for the OPAD to XOR with the key
        uint8_t *keyXORopad;

        // Convert the secret_hex to binary form
        uint8_t encoders[64];
        int i = 0;
        for (i = 0; i < strlen(secret_hex)/2; i++)
            sscanf((i*2)+secret_hex, "%2x", &encoders[i]);
        
        // Pad the rest of the binary key with 0's
        // We pad it to keep it the same length as the 
        // XOR's. May not be strictly necessary
        for (i = strlen(secret_hex)/2; i < 64; i++)
            encoders[i] = 0;
        
        // Pad the beginning of the message with 0's
        uint8_t counter[8];
        for (i = 0; i < 7; i++)
            counter[i] = 0;

        // Get the current time in Seconds
        int seconds;
        // Divide by the valid period which is 30
        seconds = (int)(time(NULL))/30;

        // Convert time into 4 Byte (integer is 32 bits)
        // and store in big endian order
        int c = 0;
        for (i = 7; i >= 4; i--)
        {
            counter[i] = ((seconds >> (c*8)) & 0xff);
            c++;
        }
 
        // The sha is of the form
        // SHA1(K XOR opad, SHA1(K XOR ipad, text))
         
        // First store 0's in the arrays
        keyXORipad = (uint8_t*)(calloc(64, sizeof(uint8_t)));
        keyXORopad = (uint8_t*)(calloc(64, sizeof(uint8_t)));
        // Store the keys in each respective XOR array
        memcpy( keyXORipad, encoders, 64);
        memcpy( keyXORopad, encoders, 64);

        // Compute the inner and outer XOR's
        for (i = 0; i < 64; i++) {
                keyXORipad[i] ^= 0x36;
                keyXORopad[i] ^= 0x5c;
        }

        // Inner SHA1
        
        // Initialize context
        sha1_init(&context); 
        // Update with the Inner Pad
        sha1_update(&context, keyXORipad, 64);
        // Update with the message counter
        sha1_update(&context, counter, 8);
        // Store the output in digest; 20 Bytes
        uint8_t digest[20];
        sha1_final(&context, digest);
        
        // Outer Hash
        
        // Initialize context 2
        sha1_init(&context2);
        // Updatew with outer pad and output of inner hash
        sha1_update(&context2, keyXORopad, 64);
        sha1_update(&context2, digest, 20);
        // Store the output of digest; 20 Bytes
        uint8_t d2[20];
        sha1_final(&context2, d2);
        
        // Truncate Output to 6 Bytes
        int value = truncate(d2, 6);
        
        // Convert Integer to String.
        char * finalResult = (char*)malloc(6);
        sprintf(finalResult,  "%6d", value);
        
        // Check if provided TOTP_string is valid
        if(strcmp(finalResult, TOTP_string) == 0)
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

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");
        
	return(0);
}
