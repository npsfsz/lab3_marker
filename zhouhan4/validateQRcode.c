#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/sha1.h"

/* In the second part of this lab, you are to complete the code in validateQRcode.c in order to have it generate the HOTP and TOTP values from the secret and then verify whether the user has provided correct values.*/

/* you will need to use the provided SHA1 function to create an HMAC.
   please see the RFC docs included in the lab for the description of the inner/outer padding, and how to truncate the HMAC to only six characters for the output.
   when calculating the HMAC, you should be including the secret in its binary form
   Note that both TOTP and HOTP use identical HMAC calculations: the only difference is whether they include the time or a counter in the hashed value. 
   As a result, you do not need to implement multiple HMAC implementations.
*/

/* From RFC2104
   B is the byte-length of such (B=64 for SHA-1)
   L the byte-length of hash outputs (L=16 for MD5, L=20 for SHA-1).
   The secret key K can be of any length up to B, the block length of the hash function.
   Applications that use keys longer than B bytes will first hash the key using H and then use the resultant L byte string as the actual key to HMAC

ipad = the byte 0x36 repeated B times
opad = the byte 0x5C repeated B times.

  To compute HMAC over the data ‘text’ we perform
      H(K XOR opad, H(K XOR ipad, text))

*/
int B = 64;
int L = 20;


/* DYNAMIC TRUNCATE (STEPS 2 AND 3)
String = String[0]...String[19]
OffsetBits are the lower order 4 bits of the String[19]
	Offset = StToNum(OffsetBits)
	P = String[Offset]...String[Offset+3]
Return the last 31 bits of P
*/

static long
dynamic_truncate_HOTP(char * secret_hex) 
{
	// hmac_result is a byte array
	// counter is 1
	// otpauth://hotp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&counter=1
	uint8_t counter[] = {0,0,0,0,0,0,0,1};

	int i, str_len = strlen(secret_hex)/2;
	uint8_t ipad[B];
	uint8_t opad[B];
	uint8_t K[B];
	uint8_t key[str_len];

	SHA1_INFO ctx;
	uint8_t hmac_result[SHA1_DIGEST_LENGTH];
	uint8_t ipad_sha[SHA1_DIGEST_LENGTH];

	// can write byte from string
	/* A string is an array of bytes.

	If you want to display the ASCII value of each character in hex form, you would simply do something like:

	while (*str != 0)
  		printf("%02x ", (unsigned char) *str++);
	*/
	for (i = 0; i < str_len; i++) {
        	sscanf(secret_hex + 2*i, "%02x", &key[i]);
    	}

 	// (1) append zeros to the end of K to create a B byte string (e.g., if K is of length 20 bytes and B=64, then K will be appended with 44 zero bytes 0x00)
	for(i = 0;i < 10; i++){
		K[i] = key[i];
	}
	for(i = 10;i < B; i++){
		K[i] = 0x00;
	}

 	// (2) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with ipad
	for (i = 0; i < B; i++) {
		ipad[i] = K[i] ^ 0x36;
	}

 	// (3) append the stream of data ’text’ to the B byte string resulting from step (2)
 	// (4) apply H to the stream generated in step (3)
	sha1_init(&ctx);
     	sha1_update(&ctx, ipad, B);
     	// keep calling sha1_update if you have more data to hash...	
	sha1_update(&ctx, counter, 8);
	// The final call to sha1_final() will write the SHA1 hash of the data (in a binary form) into the
	// sha[] array (which you can then use in your HMAC calculation).
 	sha1_final(&ctx, ipad_sha);

 	// (5) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with opad
	for (i = 0; i < B; i++) {
		opad[i] = K[i] ^ 0x5c;
	}

 	// (6) append the H result from step (4) to the B byte string resulting from step (5) 
 	// (7) apply H to the stream generated in step (6) and output the result
	sha1_init(&ctx);
	sha1_update(&ctx, opad, B);
     	// keep calling sha1_update if you have more data to hash...	
	sha1_update(&ctx, ipad_sha, L);
	// The final call to sha1_final() will write the SHA1 hash of the data (in a binary form) into the
	// sha[] array (which you can then use in your HMAC calculation).
 	sha1_final(&ctx, hmac_result);

	// 0xf used to get lower order 4 bits
	// 19th index of String
	int offset = hmac_result[19] & 0xf;
	//printf("The offset is %d\n", offset);

	// the first byte is masked with 0x7f because we treat it as a 31 bit, unsigned, big-endian integer
	long binary_code = (hmac_result[offset] & 0x7f) << 24
		| (hmac_result[offset+1] & 0xff) << 16
		| (hmac_result[offset+2] & 0xff) << 8
		| (hmac_result[offset+3] & 0xff);
	return binary_code;
}


/*
Step 1: Generate an HMAC-SHA-1 value HS = HMAC-SHA-1(K,C) where K is the secret key, C is the counter and HS is a 20-byte (160-bit string)
Step 2: Generate a 4-byte string through dynamic truncation Sbits = DT(HS)
Step 3: Compute SNum = StToNum(Sbits) where StToNum returns the binary representation of Sbits (between 0...2^(31)-1)
	D = Snum % 10^digit, where digits is the number of digits in an HOTP value (D is between 0...10^(digit)-1)
*/

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{

	long DBC = dynamic_truncate_HOTP(secret_hex);
	//printf("The HOTP is %d\n", DBC);
	// we are generating a 6 digit HOTP
	long HOTP = DBC % 1000000;

	//printf("The HOTP really is %d\n", HOTP);

	//printf("HOTP given is %d", atoi(HOTP_string));

	if(HOTP == atoi(HOTP_string)) {
		return 1;
	}

	return (0);
}


/*
   From RFC6238
   We define TOTP as TOTP = HOTP(K, T), where T is an integer and represents the number of time steps between the initial counter time T0 and the current Unix time.
   T = (Current Unix time - T0) / X, default X = 30 seconds
*/
int X = 30;

static long
dynamic_truncate_TOTP(char * secret_hex) 
{
	int i, str_len = strlen(secret_hex)/2;
	// hmac_result is a byte array
	// use time instead of a counter for TOTP
    	long T = time(NULL)/X;
	/*
	
	*/
	uint8_t T_bytes[8];
	//copy T bit by bit into T_byte
   	for (i = 7; i >= 0; i--) {
   		T_bytes[i] = T;
   		T >>= 8;
   	}

	uint8_t ipad[B];
	uint8_t opad[B];
	uint8_t K[B];
	uint8_t key[str_len];

	SHA1_INFO ctx;
	uint8_t hmac_result[SHA1_DIGEST_LENGTH];
	uint8_t ipad_sha[SHA1_DIGEST_LENGTH];

	for (i = 0; i < str_len; i++) {
        	sscanf(secret_hex + 2*i, "%02x", &key[i]);
    	}

 	// (1) append zeros to the end of K to create a B byte string (e.g., if K is of length 20 bytes and B=64, then K will be appended with 44 zero bytes 0x00)
	for(i = 0;i < 10; i++){
		K[i] = key[i];
	}
	for(i = 10;i < B; i++){
		K[i] = 0x00;
	}

 	// (2) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with ipad
	for (i = 0; i < B; i++) {
		ipad[i] = K[i] ^ 0x36;
	}

 	// (3) append the stream of data ’text’ to the B byte string resulting from step (2)
 	// (4) apply H to the stream generated in step (3)
	sha1_init(&ctx);
     	sha1_update(&ctx, ipad, B);
     	// keep calling sha1_update if you have more data to hash...	
	sha1_update(&ctx, T_bytes, 8);
	// The final call to sha1_final() will write the SHA1 hash of the data (in a binary form) into the
	// sha[] array (which you can then use in your HMAC calculation).
 	sha1_final(&ctx, ipad_sha);

 	// (5) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with opad
	for (i = 0; i < B; i++) {
		opad[i] = K[i] ^ 0x5c;
	}

 	// (6) append the H result from step (4) to the B byte string resulting from step (5) 
 	// (7) apply H to the stream generated in step (6) and output the result
	sha1_init(&ctx);
	sha1_update(&ctx, opad, B);
     	// keep calling sha1_update if you have more data to hash...	
	sha1_update(&ctx, ipad_sha, L);
	// The final call to sha1_final() will write the SHA1 hash of the data (in a binary form) into the
	// sha[] array (which you can then use in your HMAC calculation).
 	sha1_final(&ctx, hmac_result);

	// 0xf used to get lower order 4 bits
	// 19th index of String
	int offset = hmac_result[19] & 0xf;
	//printf("The offset is %d\n", offset);

	// the first byte is masked with 0x7f because we treat it as a 31 bit, unsigned, big-endian integer
	long binary_code = (hmac_result[offset] & 0x7f) << 24
		| (hmac_result[offset+1] & 0xff) << 16
		| (hmac_result[offset+2] & 0xff) << 8
		| (hmac_result[offset+3] & 0xff);
	return binary_code;
}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	long DBC = dynamic_truncate_TOTP(secret_hex);
	//printf("The TOTP is %d\n", DBC);
	// we are generating a 6 digit TOTP
	long TOTP = DBC % 1000000;

	//printf("The TOTP really is %d\n", TOTP);

	//printf("TOTP given is %d", atoi(TOTP_string));

	if(TOTP == atoi(TOTP_string)) {
		return 1;
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

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
