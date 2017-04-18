#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <time.h>

#include "lib/sha1.h"

uint8_t hexToBinary(char hex){
	uint8_t binary;

	switch(hex){
		case '0':
			binary = 0b0000;
			break;
		case '1':
			binary = 0b0001;
			break;
		case '2':
			binary = 0b0010;
			break;
		case '3':
			binary = 0b0011;
			break;
		case '4':
			binary = 0b0100;
			break;
		case '5':
			binary = 0b0101;
			break;
		case '6':
			binary = 0b0110;
			break;
		case '7':
			binary = 0b0111;
			break;
		case '8':
			binary = 0b1000;
			break;
		case '9':
			binary = 0b1001;
			break;
		case 'A':
			binary = 0b1010;
			break;
		case 'B':
			binary = 0b1011;
			break;
		case 'C':
			binary = 0b1100;
			break;
		case 'D':
			binary = 0b1101;
			break;
		case 'E':
			binary = 0b1110;
			break;
		case 'F':
			binary = 0b1111;
			break;
	}

	return binary;
}



static int
validateHOTP(char * secret_hex, char * HOTP_string)
{

	int i;
	int length = strlen(secret_hex);
	int n = 512; //hash block size (from lecture slides)
	int ni = n/8; //number indexes for the arrays
	uint8_t key[ni];
	uint8_t counter[8];


	counter[0] = 0x0;
	counter[1] = 0x0;
	counter[2] = 0x0;
	counter[3] = 0x0;
	counter[4] = 0x0;
	counter[5] = 0x0;
	counter[6] = 0x0;
	counter[7] = 0x1;

	/*printf("counter: ");
	for(i = 0; i < 8; i++)
		printf("%x ", counter[i]);
	printf("\n");*/

	///////////////////////////////////////////////////////////////
	////////////////////////////Step 1/////////////////////////////
	///////////////////////////////////////////////////////////////
	//calculate the HMAC-SHA-1(K,C)

	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////
	//set up inital key

	//convert char[] into uint8_t[]
	int count = 0;
	for(i = 0; i < 10; i++){
		key[i] = (hexToBinary(secret_hex[count]) << 4); 
		count += 2;
	}

	count = 1;
	for(i = 0; i < 10; i++){
		key[i] = key[i] | hexToBinary(secret_hex[count]); 
		count += 2;
	}

	/*
	printf("\n");
	printf("key :");
	for(i = 0; i < 10; i++)
		printf(" %02x ", key[i]);
	printf("\n\n");*/

	//add zero padding to fill up the key
	for(i = 10; i < ni; i++){
		key[i] = 0x00;
	}

	///////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////
	//HMAC = H( key1 || H( key2 || message ) )
	// || = concatenate
	// key1 = key XOR opad, key2 = key XOR ipad
	// opad = 0x5c5c.....5c5c for n bits 
	// ipad = 0x3636.....3636 for n bits

	//create key1 and key2
	uint8_t key1[ni];
	uint8_t key2[ni];

	//XOR key with pads
	for(i = 0; i < ni; i++){
		key1[i] = key[i] ^ 0x5c; //key xor opad
		key2[i] = key[i] ^ 0x36; //key xor ipad
	}

	/*printf("key1 :");
	for(i = 0; i < ni; i++)
		printf(" %02x", key1[i]);
	printf("\n\n");


	printf("key2 :");
	for(i = 0; i < ni; i++)
		printf(" %02x", key2[i]);
	printf("\n\n");*/


	///////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////
	//HMAC = H( key1 || H( key2 || message ) )
	//message in our case is the counter value

	SHA1_INFO ctxInner;
	uint8_t H_Inner[SHA1_DIGEST_LENGTH];

	sha1_init(&ctxInner);

	//key2 || counter
	sha1_update(&ctxInner, key2, ni);
	sha1_update(&ctxInner, counter, 8);

	//H(key2 || counter)
	sha1_final(&ctxInner, H_Inner);

	/*printf("H_Inner :");
	for(i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf(" %02x ", H_Inner[i]);
	printf("\n");*/

	///////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////
	//HMAC = H( key1 || H_Inner )
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);

	//key1 || H_Inner
	sha1_update(&ctx, key1, ni);
	sha1_update(&ctx, H_Inner, SHA1_DIGEST_LENGTH);

	//H( key1 || H_Inner )
	sha1_final(&ctx, sha);

	/*printf("hmac : ");
	for(i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf(" %02x ", sha[i]);
	printf("\n");*/

	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////


	///////////////////////////////////////////////////////////////
	//////////////////////////Step 2///////////////////////////////
	///////////////////////////////////////////////////////////////
	//DT(HMAC)

	uint8_t offsetBits = sha[19] & 0x0f; //get low-order 4 bits of [19]
	//printf("offsetBits : %02x\n", offsetBits);

	//convert offsetBits binary value to a number
	int offset = (int)offsetBits;
	//printf("offset : %d\n", offset);

	//concatenate [offset] ... [offset+3] into a 32 bit number
	uint32_t sbits32 = (0x00000000 | (sha[offset] << 24)) |
	 				(0x00000000 | (sha[offset + 1] << 16)) |
					(0x00000000 | (sha[offset + 2] << 8)) |
					(0x00000000 | (sha[offset + 3] )) ;

	//printf("sha[offset] : %x\nsha[offset+1] : %x\nsha[offset+2] : %x\nsha[offset+3] : %x\n",
	//		sha[offset], sha[offset+1], sha[offset+2], sha[offset+3]);
	//printf("sbits32 : %x\n", sbits32);

	//filter out for the last 31 bits
	uint32_t sbits = sbits32 & 0x7fffffff;
	//printf("sbits : %x\n", sbits);

	///////////////////////////////////////////////////////////////
	//////////////////////////Step 3///////////////////////////////
	///////////////////////////////////////////////////////////////

	int Snum = (int)sbits; //convert binary to usable number
	//printf("Snum : %d\n", Snum);

	//Snum mod 10 ^ Digit where Digit = 6
	//Digit value found from RFC doc in the example
	int HOTP = Snum % 1000000;

	//printf("HOTP : %d\n", HOTP);
	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////

	int HOTPGiven = atoi(HOTP_string);

	//printf("HOTP Given : %d\n", HOTPGiven);

	if(HOTP == HOTPGiven)
		return 1;
	return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int i;
	int length = strlen(secret_hex);
	int n = 512; //hash block size (from lecture slides)
	int ni = n/8; //number indexes for the arrays
	uint8_t key[ni];
	uint8_t currTime[8];

	int period = 30;
	int to = 0;

	time_t t = time(NULL);
	uint32_t currTime32 = (uint32_t)t;

	//printf("current time as int = %d\n", currTime32);

	//do TOTP calculation
	currTime32 = (currTime32 - to)/period;

	//printf("adjusted current time = %d\n", currTime32);

	currTime[0] = 0x0;
	currTime[1] = 0x0;
	currTime[2] = 0x0;
	currTime[3] = 0x0;
	currTime[4] = (uint8_t)(currTime32 >> 24);
	currTime[5] = (uint8_t)(currTime32 >> 16);
	currTime[6] = (uint8_t)(currTime32 >> 8);
	currTime[7] = (uint8_t)(currTime32);

	/*printf("current time = ");
	for(i = 0; i < 8; i++)
		printf("%x", currTime[i]);
	printf("\n");*/

	///////////////////////////////////////////////////////////////
	////////////////////////////Step 1/////////////////////////////
	///////////////////////////////////////////////////////////////
	//calculate the HMAC-SHA-1(K,C)

	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////
	//set up inital key

	//convert char[] into uint8_t[]
	int count = 0;
	for(i = 0; i < 10; i++){
		key[i] = (hexToBinary(secret_hex[count]) << 4); 
		count += 2;
	}

	count = 1;
	for(i = 0; i < 10; i++){
		key[i] = key[i] | hexToBinary(secret_hex[count]); 
		count += 2;
	}

	/*printf("\n");
	printf("key :");
	for(i = 0; i < 10; i++)
		printf(" %02x ", key[i]);
	printf("\n\n");*/

	//add zero padding to fill up the key
	for(i = 10; i < ni; i++){
		key[i] = 0x00;
	}

	///////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////
	//HMAC = H( key1 || H( key2 || message ) )
	// || = concatenate
	// key1 = key XOR opad, key2 = key XOR ipad
	// opad = 0x5c5c.....5c5c for n bits 
	// ipad = 0x3636.....3636 for n bits

	//create key1 and key2
	uint8_t key1[ni];
	uint8_t key2[ni];

	//XOR key with pads
	for(i = 0; i < ni; i++){
		key1[i] = key[i] ^ 0x5c; //key xor opad
		key2[i] = key[i] ^ 0x36; //key xor ipad
	}

	/*printf("key1 :");
	for(i = 0; i < ni; i++)
		printf(" %02x", key1[i]);
	printf("\n\n");


	printf("key2 :");
	for(i = 0; i < ni; i++)
		printf(" %02x", key2[i]);
	printf("\n\n");*/


	///////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////
	//HMAC = H( key1 || H( key2 || message ) )
	//message in our case is the counter value

	SHA1_INFO ctxInner;
	uint8_t H_Inner[SHA1_DIGEST_LENGTH];

	sha1_init(&ctxInner);

	//key2 || counter
	sha1_update(&ctxInner, key2, ni);
	sha1_update(&ctxInner, currTime, 8);

	//H(key2 || counter)
	sha1_final(&ctxInner, H_Inner);

	/*printf("H_Inner :");
	for(i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf(" %02x ", H_Inner[i]);
	printf("\n");*/

	///////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////
	//HMAC = H( key1 || H_Inner )
	SHA1_INFO ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);

	//key1 || H_Inner
	sha1_update(&ctx, key1, ni);
	sha1_update(&ctx, H_Inner, SHA1_DIGEST_LENGTH);

	//H( key1 || H_Inner )
	sha1_final(&ctx, sha);

	/*printf("hmac : ");
	for(i = 0; i < SHA1_DIGEST_LENGTH; i++)
		printf(" %02x ", sha[i]);
	printf("\n");*/

	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////


	///////////////////////////////////////////////////////////////
	//////////////////////////Step 2///////////////////////////////
	///////////////////////////////////////////////////////////////
	//DT(HMAC)

	uint8_t offsetBits = sha[19] & 0x0f; //get low-order 4 bits of [19]
	//printf("offsetBits : %02x\n", offsetBits);

	//convert offsetBits binary value to a number
	int offset = (int)offsetBits;
	//printf("offset : %d\n", offset);

	//concatenate [offset] ... [offset+3] into a 32 bit number
	uint32_t sbits32 = (0x00000000 | (sha[offset] << 24)) |
	 				(0x00000000 | (sha[offset + 1] << 16)) |
					(0x00000000 | (sha[offset + 2] << 8)) |
					(0x00000000 | (sha[offset + 3] )) ;

	//printf("sha[offset] : %x\nsha[offset+1] : %x\nsha[offset+2] : %x\nsha[offset+3] : %x\n",
	//		sha[offset], sha[offset+1], sha[offset+2], sha[offset+3]);
	//printf("sbits32 : %x\n", sbits32);

	//filter out for the last 31 bits
	uint32_t sbits = sbits32 & 0x7fffffff;
	//printf("sbits : %x\n", sbits);

	///////////////////////////////////////////////////////////////
	//////////////////////////Step 3///////////////////////////////
	///////////////////////////////////////////////////////////////

	int Snum = (int)sbits; //convert binary to usable number
	//printf("Snum : %d\n", Snum);

	//Snum mod 10 ^ Digit where Digit = 6
	//Digit value found from RFC doc in the example
	int TOTP = Snum % 1000000;

	//printf("TOTP : %d\n", TOTP);
	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////

	int TOTPGiven = atoi(TOTP_string);

	//printf("TOTP Given : %d\n", TOTPGiven);

	if(TOTP == TOTPGiven)
		return 1;
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
