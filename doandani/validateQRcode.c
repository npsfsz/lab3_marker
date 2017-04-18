#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

//CALCULATES THE HOTP ALGORITHM (minus %100000)
//TOTP AND HOTP are the same apart from the count value being UNIX_TIME/30 in TOTP
static int getHMAC(char * secret, int count){
	SHA1_INFO ctx;
	uint8_t hmac_first[SHA1_DIGEST_LENGTH]; //HMAC is 20 bytes
	uint8_t hmac_result[SHA1_DIGEST_LENGTH]; //HMAC is 20 bytes
	uint8_t innerMsg[8]; //Moving factor is set as 8 bytes
	uint8_t kXORopad[64]; //0x36 XOR KEY = 64 bytes
	uint8_t kXORipad[64]; //0x5c XOR KEY = 64 bytes
	int i;
	
	//Convert the count to an 8 byte value
	for (i = 0; i < 7; i++)
		innerMsg[i] = 0x00;

	innerMsg[7] = (uint8_t) count & 0xff;
	innerMsg[6] = (uint8_t) (count >> 8) & 0xff;
	innerMsg[5] = (uint8_t) (count >> 16) & 0xff;
	innerMsg[4] = (uint8_t) (count >> 24) & 0xff;

	//for (i = 0; i < 7; i++)
	//	printf("%x\n", innerMsg[i]);

	//Convert the secret into HEX - we are to right pad the secret with 0s
	uint8_t hexSecret[64];

	for (i = 0; i < 10; i++){
		//http://stackoverflow.com/questions/33982870/how-to-convert-char-array-to-hexadecimal
		hexSecret[i] = ('A' <= secret[i*2] && secret[i*2] <= 'F'  ? (10 + secret[i*2] - 'A'):(secret[i*2] - '0'))<<4 |  
			('A' <= secret[i*2+1] && secret[i*2+1] <= 'F'  ? (10 + secret[i*2+1] - 'A'):(secret[i*2+1] - '0'));
		//printf("%d - %x\n", i, hexSecret[i]);
	}

	for (i = 10; i < 64; i++){
		hexSecret[i] = 0x00;
	}

	for (i = 0; i < 64; i++){
		kXORipad[i] = 0x36 ^ hexSecret[i];
		kXORopad[i] = 0x5c ^ hexSecret[i];
	}

	//for (i = 0; i < 64; i++)
	//printf("%2d %2x %2x\n", i, kXORipad[i], kXORopad[i]);

	//https://books.google.ca/books?id=bJJUVNGbrLsC&pg=PA155&lpg=PA155&dq=hmac+36&source=bl&ots=sZ-g2w8Uqg&sig=o6fjdpmDzleyqaS9Yz8ZKXgWtXc&hl=en&sa=X&ved=0ahUKEwj8ua61zODSAhVE5IMKHRPnAH4Q6AEIPTAF#v=onepage&q=hmac%2036&f=false
	//Inner HMAC-SHA1 
	sha1_init(&ctx);
	sha1_update(&ctx, kXORipad, 64);
	sha1_update(&ctx, innerMsg, 8);
	sha1_final(&ctx, hmac_first);
	//SHA1 has size 20 => 160 bits

	//Outer HMAC-SHA1
	sha1_init(&ctx);
	sha1_update(&ctx, kXORopad, 64);
	sha1_update(&ctx, hmac_first, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, hmac_result);

	//Truncate function
	int offset = hmac_result[19] & 0xf ;
	int bin_code = (hmac_result[offset] & 0x7f) << 24
	| (hmac_result[offset+1] & 0xff) << 16
	| (hmac_result[offset+2] & 0xff) << 8
	| (hmac_result[offset+3] & 0xff) ;
}


static int
validateHOTP(char * secret, char * HOTP_string)
{
	int counter = 1;

	//Get the HMAC value
	int hashValue = getHMAC(secret, counter);

	//Mod to get HOTP value
	int hotpValue = hashValue % 1000000;
	//printf("HOTP generated : %d\n", hotpValue);

	//Convert int to string and compare
	char hotpStr[7];
	snprintf(hotpStr, 7, "%d", hotpValue);

	if (strcmp(hotpStr, HOTP_string) == 0)
		return 1;

	return (0);
}

//T = unix_time/X
//TOTP=HOTP(secret, T)
static int
validateTOTP(char * secret, char * TOTP_string)
{
	//Get time in seconds and divide by X where X = 30
	int T = ((int) time (NULL))/30;

	//Get the HMAC value and mod it to get the TOTP value
	int hashValue = getHMAC(secret, T);
	int totpValue = (int)hashValue % 1000000;

	//printf("TOTP generated : %d\n", totpValue);

	//Convert the int to a string and compare it
	char totpStr[7];
	snprintf(totpStr, 7, "%d", totpValue);

	if (strcmp(totpStr, TOTP_string) == 0)
		return 1;	

	return (0);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret,
		HOTP_value,
		validateHOTP(secret, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret, TOTP_value) ? "valid" : "invalid");

	return(0);
}
