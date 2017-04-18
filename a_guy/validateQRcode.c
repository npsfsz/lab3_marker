#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

int checkHMAC(uint8_t* bytes_secret, uint8_t* data, char* OTP_string){
    //set up ipad and opad 
   // and use HMAC = H[(K XOR opad) || H((K XOR ipad) || M)]
    
    SHA1_INFO ctx;
    SHA1_INFO ctx2;
   
    uint8_t ipad[64];
    uint8_t opad[64];
    unsigned int initial[64];
    //unsigned int nullpad[54] = {0}	
    int i;
    for(i=0;i<64;i++){
	initial[i] = 0x00;
    }
    for(i=0;i<10;i++){
	initial[i] = bytes_secret[i];
       }
    for(i=0;i<64;i++){
      opad[i] = initial[i]^0x5c;				
      }
    for(i=0;i<64;i++){
           ipad[i] = initial[i]^0x36;				
       }
    uint8_t mac1[SHA1_DIGEST_LENGTH];
    uint8_t mac2[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_init(&ctx2);
    sha1_update(&ctx, ipad, SHA1_BLOCKSIZE);
    sha1_update(&ctx, data, sizeof(data));
    sha1_final(&ctx, mac1);
  
    sha1_update(&ctx2, opad, SHA1_BLOCKSIZE);
    sha1_update(&ctx2, mac1, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx2, mac2);
    
   //code from the rfc document
    int offset = mac2[19] & 0xf ;
    int bin_code = (mac2[offset] & 0x7f) << 24
        | (mac2[offset+1] & 0xff) << 16
        | (mac2[offset+2] & 0xff) << 8
        | (mac2[offset+3] & 0xff) ;

	//obtain the value and convert to int    
    int val = bin_code % 1000000;

	int strvalue = atoi(OTP_string);
    
    //printf("computed value: %d", val);
    //printf("given value: %d", strvalue);
	if(val == strvalue){
        //printf("match\n");
        return 1;
    }
    else{
        //printf("not match\n");
        return 0;
    }
    
    
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    
    int length = strlen(secret_hex);
    uint8_t bytes_secret[10];
    int i;

    //converting hex string to byte array 
       //(taken from http://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c)
    for (i = 0; i < (strlen(secret_hex)/2); i++) {
        sscanf(secret_hex+2*i,"%02x",&bytes_secret[i]);
    }
    
    uint8_t counter[8] = {0,0,0,0,0,0,0,1};
    
    //int counter[] = {0,0,0,0,0,0,0,1};
    int hs = checkHMAC(bytes_secret, counter, HOTP_string);
    
    if(hs == 1) return 1;
    else return 0;
    
}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    
    uint8_t bytes_secret[10];
    int i;
    int timerperiod = 30;
    int length = strlen(secret_hex);
    for (i = 0; i < (length / 2); i++) {
        sscanf(secret_hex + 2*i, "%02x", &bytes_secret[i]);
        //printf("bytearray %d: %02x\n", i, bytes_secret[i]);
    }
    
    int t = time(NULL)/timerperiod;
    //int i;
    uint8_t timearray[8]; 
    for( i = 7; i >= 4 ; i--){
        timearray[i] = t;
	//printf("%u",timer[i]);        
	t>>=8;
	//printf("..%d", t);
	
    } 

    for(i = 0; i<4;i++){
	timearray[i] = 0;
	}
    int res = checkHMAC(bytes_secret, timearray, TOTP_string);
    if(res == 1) return 1;
    else return 0;
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
