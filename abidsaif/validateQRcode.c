// Submission copy
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "lib/sha1.h"

int sze = 64;
int hex_to_int (char c)
{
    if ((c >= '0') && (c <= '9'))
        return c - '0';
    if ((c >= 'A') && (c <= 'F'))
        return 10 + c - 'A';
    return -1;
}

uint8_t* hexCharArrayToUint8Array(char* secret_hex) {
	int sze = strlen(secret_hex)/2; 
	 uint8_t *temp = malloc(strlen(secret_hex)/2);
	 int i=0;
	 uint8_t zero = 0;
	 for (i=0;i<sze;i++) {
		 temp[i] = zero;
	 }

	 uint8_t *head = temp;
	 int j =0;
	 for (i=0;i<strlen(secret_hex);i=i+2){
        uint8_t hex1 = (uint8_t)hex_to_int (secret_hex[i]);
        uint8_t hex2 = (uint8_t)hex_to_int (secret_hex[i+1]);
		// This is so if we have 1, 2 -> 0000 0001, 0000 0010 then hex1<<4|hex2 --> 0001 0010
        temp[j] = (hex1<<4|hex2);
		j++;
    }
	return head;
}


static int work(char *secret_hex, uint8_t* C, char* str) {
	int i=0;
	uint8_t zero = 0; // 0000 0000

	// Step1: secret_hex in bytes -> 0x12 0x34 0x56 0x78 0x90 0x00 ... (padded to 64 bytes)
	uint8_t *hexArray = hexCharArrayToUint8Array(secret_hex);
	uint8_t K[64];
	for (i=0; i<64; i++) {
		K[i] = zero;
	}


	// Step 2: copy over our 10 bytes from hexArray into K, leaving the rest as a "pad"
	for(i=0;i<10;i++){
		K[i] = hexArray[i];
	}


	// At this point we have K which is 64 bytes (10 is the key, 54 is padded 0's')

	// Step3: Define the repeated hex value which will show up in the inner padding and outer padding
	uint8_t opadHex = 0x36;
	uint8_t ipadHex = 0x5c;


	// Step4: Define the key1, and key2 -> the secret key xored with the respective pads
	uint8_t opadXORK[64];
	uint8_t ipadXORK[64]; 
	for (i=0;i<64;i++){
		ipadXORK[i] = zero;
		opadXORK[i] = zero;
	}

	// Step5: xor key with pad's
	for (i=0;i<sze;i++) {
		opadXORK[i] = K[i] ^ ipadHex;
		ipadXORK[i] = K[i] ^ opadHex;
	}

	// Step 6: Concat counter with key1 and take a sha1 hash
	// Step6: Sha1 of the inner key Concatted with the counter
	SHA1_INFO ctx;
	uint8_t innerHash[64]; 
	for (i=0;i<64;i++){
		innerHash[i] = zero;
	}

    sha1_init(&ctx);
    sha1_update(&ctx, ipadXORK, 64);
	sha1_update(&ctx, (const uint8_t*) C, 8);
	sha1_final(&ctx, innerHash);

	// Step7: Sha1 of the outer key contated with the innerHash
	SHA1_INFO ctx2;
	uint8_t hmac[SHA1_DIGEST_LENGTH];
	for (i=0;i<64;i++){
		hmac[i] = 0x00;
	}

    sha1_init(&ctx2);
    sha1_update(&ctx2, opadXORK, 64);
    sha1_update(&ctx2, innerHash, 20);
    sha1_final(&ctx2, hmac);


	// Step 8: The current hamc val is 20 bytes, we need to make this shorter
	// First we will perform what rfc4226 called "dynamic truncation"
	// to get this value into a 4 byte value (8*4 = 32 bits)
	 int offset = hmac[19] & 0xf;
	 uint8_t mask[] = {0xff,0xff,0xff,0x7f}; 
	 long  val = 0;
	  val = ((hmac[offset] & mask[3])<< 24) |  
	  ((hmac[offset+1] & mask[2]) << 16)|
	  ((hmac[offset+2] & mask[1]) << 8)|
	  ((hmac[offset+3] & mask[0]));
	
	// Step 9: Now that we have a 4 byte (32 bit number), we can truncate this number
	// To be a certain conviniant length. we will do 6 digits.
	// To do this, we will mod our 32 bit val by 1000000
	long fv = val %  1000000;
	if (atoi(str) == fv){
		return 1;
	}

	return 0;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{	
	// In 64 bits, a 1 is signified as 0000 0000 ... until the last byte which is 0000 0001. 
	uint8_t one = 1; // 0000 0001 
	uint8_t zero = 0; //  0000 0000 

	int i = 0;
	uint8_t C[7];
	for (i=0; i < 7; i++) {
		C[i] = zero;
	}

	C[i] = one;

	return work(secret_hex, C, HOTP_string);
	
} 

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{

	long long T = time(NULL)/30; // This is a 8 byte number, 8*8 = 64 bits. 
	// In order to push this into an 8 element array with each elements holding 8 bytes we need to do some shifiting in the following way
	// lets say T = 1111 2222  3333 4444  5555 6666  7777 8888  9999 aaaa  bbbb cccc  dddd eeee  ffff gggg
	// The goal is to keep shifting the bits until they take the location of the first 8 bits (ffff, gggg) 
	// and fill those in the array, then shift again and fill the next batch etc.
	uint8_t C[7];

	// The comments will show the bit shifting as per our example, of course the actual value depends on T
	C[0] = T >> 56; // 1111 2222
	C[1] =  T >> 48; // 3333 4444 
	C[2] = T >> 40; // 5555 6666
	C[3] = T >> 32; // 7777 8888
	C[4] = T >> 24; // 9999 aaaa
	C[5] = T >> 16; // bbbb cccc 
	C[6] = T >> 8; /// dddd eeee
	C[7] = T; // ffff gggg


	return work(secret_hex, C, TOTP_string);
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

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
