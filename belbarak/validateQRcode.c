#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <inttypes.h>
#include "lib/sha1.h"

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	
	char* key=secret_hex;
	
	SHA1_INFO ctx;
	unsigned char inner_key[65];
	unsigned char outer_key[65];
	
	
	uint8_t digest[SHA1_DIGEST_LENGTH]; 
	uint8_t sha[SHA1_DIGEST_LENGTH];
	
	bzero(inner_key, sizeof(inner_key));
	bcopy(key, inner_key, 20);
	bzero(outer_key, sizeof(outer_key));
	bcopy(key, outer_key, 20);
	
	//xor key with inner and outer 
	int i;
	for(i=0; i<64; i++){
		inner_key[i] ^= 0x36;
		
		outer_key[i] ^= 0x5c;
		}
	
	const uint8_t counter[] = {0, 0, 0, 0, 0, 0, 0, 1};
	sha1_init(&ctx);  
	sha1_update(&ctx, inner_key, 64); 
	sha1_update(&ctx, counter, 8); 
	sha1_final(&ctx, digest); 
      
	sha1_init(&ctx);
	sha1_update(&ctx, outer_key, 64); 
	sha1_update(&ctx, digest, 20); 
	sha1_final(&ctx,sha);
	
	int offset= sha[19] & 0xf;
	
	int secret_b=(sha[offset]&0x7f)<<24 | (sha[offset+1]&0xff) << 16 | (sha[offset+2] & 0xff) << 8| (sha[offset+3] & 0xff);
	
	int modulo= pow(10,6);
	int val=secret_b % modulo;
	
	if(val== atoi(HOTP_string)){
		return 1;
		}
	else {
	return (0);
    }
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	char* key=secret_hex;
	
	SHA1_INFO ctx;
	unsigned char inner_key[65];
	unsigned char outer_key[65];
	
	
	uint8_t digest[SHA1_DIGEST_LENGTH]; 
	uint8_t sha[SHA1_DIGEST_LENGTH];
	
	bzero(inner_key, sizeof(inner_key));
	bcopy(key, inner_key, 20);
	bzero(outer_key, sizeof(outer_key));
	bcopy(key, outer_key, 20);
	
	//xor key with inner and outer 
	int i;
	for(i=0; i<64; i++){
		inner_key[i] ^= 0x36;
		
		outer_key[i] ^= 0x5c;
		}
		
	unsigned long long sec;
	sec = time (NULL)/30;
	
	const uint8_t counter[] = {(sec >> 56) & 0xff,(sec >> 48)&0xff,(sec >> 40)&0xff,(sec >> 32)&0xff,(sec >> 24)&0xff,(sec >> 16)&0xff,(sec >> 8)&0xff,sec&0xff};
	
	sha1_init(&ctx);  
	sha1_update(&ctx, inner_key, 64); 
	sha1_update(&ctx, counter, 8); 
	sha1_final(&ctx, digest); 
      
	sha1_init(&ctx);
	sha1_update(&ctx, outer_key, 64); 
	sha1_update(&ctx, digest, 20); 
	sha1_final(&ctx,sha);
	
	int offset= sha[19] & 0xf;
	
	int secret_b=(sha[offset]&0x7f)<<24 | (sha[offset+1]&0xff) << 16 | (sha[offset+2] & 0xff) << 8| (sha[offset+3] & 0xff);
	
	int modulo=pow(10,6);
	int val=secret_b % modulo;
	
	if(val== atoi(TOTP_string)){
		return 1;
		}
	else {
	return (0);
    }
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

	char* s_hex= secret_hex;
	char * str_secret;
	str_secret=(char*)malloc(20);
	
	//pad zeros to secret_hex
	int i;
	for(i=0; i<strlen(s_hex); i++){
		str_secret[i]=s_hex[i];
		}
		
	int j;
	for(j=strlen(s_hex); j<20; j++){
		str_secret[j]='0';
		}
		
	str_secret[20]='\0';
	

	int k,l;
	int inner, outer;
	int total[10];
	char str_b[20]="";
	for(k=0, l=0; k<20; k+=2, l+=1){
		if(str_secret[k]<= 57){
			inner=str_secret[k]-48;
			}
		else if(str_secret[k]<= 70){
			inner=str_secret[k]-55;
			}
		else if(str_secret[k]<= 102){
			inner=str_secret[k]-87;
			}
		
		if(str_secret[k+1]<= 57){
			outer=str_secret[k+1]-48;
			}
		else if(str_secret[k+1]<= 70){
			outer=str_secret[k+1]-55;
			}
		else if(str_secret[k+1]<= 102){
			outer=str_secret[k+1]-87;
			}
		total[l]=16*inner+ outer;
		str_b[l]=(char)total[l];
		
		}
	
	s_hex=str_b;
	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		str_secret,
		HOTP_value,
		validateHOTP(s_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(s_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}