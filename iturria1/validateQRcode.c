#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"

#define IPAD 0x36
#define OPAD 0x5c

void hmac_sha1(char *,char *,int,char *);
int ascii_decode_hex(char);

int
convert_string_to_hex(char *input,char *output){
	int i,count=0;
	for(i=0;i<strlen(input);i+=2){
		if(i==0 && strlen(input)%2==1){
			output[0]=ascii_decode_hex(input[0]);
			i--;
			}
		else {
			output[count]=ascii_decode_hex(input[i])*16+ascii_decode_hex(input[i+1]);
		}
		count++;
	}
	return count;
}

int
ascii_decode_hex(char input){
	if(input >= '0' && input <= '9')
		return input-'0';
	else
		return input-55;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string, char *counter)
{
	int HOTP = atoi(HOTP_string);
	char *secret = (char *)malloc(64);
	memset(secret,0,sizeof(secret));
	char *hmac = (char *)malloc(20);
	memset(hmac,0,sizeof(hmac));
	int i;


	convert_string_to_hex(secret_hex,secret);
	hmac_sha1(secret,counter,8,hmac);

	//step 1, acquire the last (lower order) 4 bits from hmac
	int offset = hmac[19] & 0x0f;
	int p = hmac[offset]<<24;
	p = p | (hmac[offset+1]<<16 & 0xff0000);
	p = p | (hmac[offset+2]<<8 & 0xff00);
	p = p | (hmac[offset+3] & 0xff);

	//we are only going to be using the first 31 bits of this 32 bit number.
	p = p & 0x7fffffff;
	p = p % 1000000;
	free(secret);
	free(hmac);
	return HOTP == p;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	int T = ((int) time(NULL))/30;
	//convert T into a hex string, where hex[7]=LSB
	int i;
	char *hex = (char *)malloc(8);
	for(i=0;i<8;i++){
			if(i<4)
				hex[i]=0;
			else
				hex[i]=(T>>((7-i)*8))&0xff;
	}
	int r = validateHOTP(secret_hex,TOTP_string,hex);
	free(hex);
	return r;


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
	
	char counter[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};	

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value,counter) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}

void hmac_sha1(char *key, char *message, int messageSize, char *output){
	//define ipad and opad
	int i;
	char ipad[64],opad[64];
	for(i=0;i<64;i++){
		ipad[i]=IPAD;
		opad[i]=OPAD;
	}

	//init sha1 ctx
	SHA1_INFO ctx1,ctx2;
	uint8_t sha1[SHA1_DIGEST_LENGTH],sha2[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx1);
	sha1_init(&ctx2);

	//our key should already be B bytes long, so lets XOR
	char *mac = (char *)malloc(64);
	for(i=0;i<64;i++){
		mac[i]=ipad[i]^key[i];
	}
	//now put each part of the data in our SHA1
	sha1_update(&ctx1,mac,64);
	sha1_update(&ctx1,message,messageSize);

	//obtain our hash
	sha1_final(&ctx1,sha1);

	//now we compute the 2nd half of our hmac. K^opad,sha1
	memset(mac,0,64);
	for(i=0;i<64;i++){
		mac[i]=opad[i]^key[i];	
	}
	//now put each part of the data in our SHA1
	sha1_update(&ctx2,mac,64);
	sha1_update(&ctx2,sha1,20);

	//obtain our final hash
	sha1_final(&ctx2,sha2);
	
	free(mac);
	for(i=0;i<20;i++){
		output[i]=sha2[i];	
	}
}
	



