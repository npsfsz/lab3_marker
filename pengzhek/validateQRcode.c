

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <inttypes.h>
#include <math.h>
#include <ctype.h>
#include <stdlib.h>
#include "lib/sha1.h"



static int
validateHOTP(char* secret_hex, char * HOTP_string)
{    
  SHA1_INFO ctx; 
  unsigned char ipad[65];//inner padding
  unsigned char opad[65];//outer padding
  
  uint8_t Inner[SHA1_DIGEST_LENGTH]; //inner hash value computed by SHA1
  uint8_t HMAC[SHA1_DIGEST_LENGTH]; //outer hash value which is the HMAC value

  char * key = secret_hex;
  int key_len = 20;


//initialize ipad and opad, then store the value of the key
//into the two strings
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memcpy(ipad, key, key_len);
    memcpy(opad, key, key_len);


//XOR ipad and opad values with the key
  int i;
  for (i=0; i<64; i++) {
   ipad[i] ^= 0x36;
   opad[i] ^= 0x5c;
  }

  const uint8_t data[] = {0,0,0,0,0,0,0,1};
  
//Compute the inner hash value Inner
  sha1_init(&ctx); //initializes a SHA_CTX structure
  sha1_update(&ctx, ipad, 64); //can be called repeatedly with chunks of the message to be hashed
  sha1_update(&ctx, data, sizeof(data));
  sha1_final(&ctx, Inner); //places the message digest in Inner
 
//Compute the outer hash value, which is the value of HMAC
  sha1_init(&ctx); 
  sha1_update(&ctx, opad, 64); 
  sha1_update(&ctx, Inner, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx,HMAC);

//Extract the binary data from HMAC
  int offset   =  HMAC[SHA1_DIGEST_LENGTH-1] & 0x0f;

  int binary_code = (HMAC[offset]  & 0x7f) << 24
           | (HMAC[offset+1] & 0xff) << 16
           | (HMAC[offset+2] & 0xff) << 8
           | (HMAC[offset+3] & 0xff);


  int chk = binary_code % 1000000;

//Truncate the HMAC to only six characters for the output
  if(chk == atoi(HOTP_string)){//check if the HOTP value only contains six digits
    return 1;
  }else{
    return 0;
  }
  
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
  SHA1_INFO ctx; 
  unsigned char ipad[65];//inner padding
  unsigned char opad[65];//outer padding
  
  uint8_t Inner[SHA1_DIGEST_LENGTH]; //inner hash value computed by SHA1
  uint8_t HMAC[SHA1_DIGEST_LENGTH]; //outer hash value which is the HMAC value

  char * key = secret_hex;
  int key_len = 20;

//initialize ipad and opad, then store the value of the key
//into the two strings
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memcpy(ipad, key, key_len);
    memcpy(opad, key, key_len);

//XOR ipad and opad values with the key
  int i;
  for (i=0; i<64; i++) {
   ipad[i] ^= 0x36;
   opad[i] ^= 0x5c;
  }

  unsigned long long sec;
  sec = time (NULL)/30;//The period for refreshing is 30s
    
  const uint8_t timer[] = {(sec >> 56) & 0xff,(sec >> 48)&0xff,(sec >> 40)&0xff,(sec >> 32)&0xff,(sec >> 24)&0xff,(sec >> 16)&0xff,(sec >> 8)&0xff,sec&0xff};

//Compute the inner hash value Inner
  sha1_init(&ctx);  //initializes a SHA_CTX structure
  sha1_update(&ctx, ipad, 64);//can be called repeatedly with chunks of the message to be hashed
  sha1_update(&ctx, timer, sizeof(timer));//places the message digest in Inner
  sha1_final(&ctx, Inner); 
  
//Compute the outer hash value, which is the value of HMAC
  sha1_init(&ctx);
  sha1_update(&ctx, opad, 64);  
  sha1_update(&ctx, Inner, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx,HMAC);

//Extract the binary data from HMAC
  int offset   =  HMAC[19] & 0x0f ;

  int binary_code = (HMAC[offset]  & 0x7f) << 24
           | (HMAC[offset+1] & 0xff) << 16
           | (HMAC[offset+2] & 0xff) << 8
           | (HMAC[offset+3] & 0xff);

//Truncate the HMAC to only six characters for the output
  int chk = binary_code % 1000000;

  if(chk == atoi(TOTP_string)){//check if the HOTP value only contains six digits
    return 1;
  }else{
    return 0;
  }
}

int main(int argc, char * argv[])
{
  
  
  if ( argc != 4 ) {
    printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
    return(-1);
  }
  
      //char output[20] = "";
    char * sec_hex = argv[1];
    char *  HOTP_val = argv[2];
    char *  TOTP_val = argv[3];   

    char* pad_String; 
    pad_String = (char *)malloc(20);
    //padding zero at the beginning
    if(strlen(sec_hex) < 20){
	int l;
  for(l = 0;l < strlen(sec_hex);l++){
  			
    pad_String[l] = sec_hex[l];
  }
  int k;
  for(k = strlen(sec_hex);k < 20;k++){
    pad_String[k] = '0';
  }
    pad_String[20] = '\0';
  }else{
    strcpy(pad_String, sec_hex);
  }

  
  int h,l; //high byte & lower byte
    int trans[10];
    char secrettrans[20]="";
    int i, j=0; 
    for(i=0;i<20;i++){
      //0-9
      if(pad_String[i]<=57){
      	if(i%2==0)
      	h=pad_String[i]-48;
        else
        l=pad_String[i]-48;
      }
      
      //A-F
      else if(pad_String[i]>=65 && pad_String[i]<=70){
      	if(i%2==0)
      	h=pad_String[i]-65+10;
        else
        l=pad_String[i]-65+10;	
      }
      	
      //a-f
	  else if(pad_String[i]>=97 && pad_String[i]<=102){
	  	if(i%2==0)
	  		h=pad_String[i]-97+10;
	  	else 
	  		l=pad_String[i]-97+10;
	  }
     //save 
      if(i%2!=0){
      	trans[j]=h*16+l;
        secrettrans[j]=(char)trans[j];
        j++;
      }
    }

  char *  secret_hex = secrettrans;
  
  assert (strlen(secret_hex) <= 20);
  assert (strlen(HOTP_val) == 6);
  assert (strlen(TOTP_val) == 6);
  
  printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
    pad_String,
    HOTP_val,
    validateHOTP(secret_hex, HOTP_val) ? "valid" : "invalid",
    TOTP_val,
    validateTOTP(secret_hex, TOTP_val) ? "valid" : "invalid");

  return(0);
}









   

