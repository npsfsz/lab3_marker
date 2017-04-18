#include <stdio.h>
#include <math.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdint.h>
#include "lib/sha1.h"

// Reference: https://opensource.apple.com/source/freeradius/freeradius-11/freeradius/src/lib/hmacsha1.c

int char_to_int(char c){
  if(c >= '0' && c <= '9') return c - 48;
  if(c >= 'a' && c <= 'f') return c - 97 + 10;
  if(c >= 'A' && c <= 'F') return c - 65 + 10;
  return -1;
}

void hmac_sha1(char * data, int data_len, char * secret_hex, int secret_hex_len,  char * digest){
  SHA1_INFO ctx;
 
  uint8_t ipad[64];
  uint8_t opad[64];
  uint8_t key[10]; // half the size of our secret_hex 
  int k=0; 
  int j=0;
  
  ipad[64] = '\0';
  opad[64] = '\0';
  key[10] = '\0';
  
  for(j; j < 20; j+=2){
    key[k] = char_to_int(secret_hex[j]) * pow(16, 1) + char_to_int(secret_hex[j+1]) * pow(16, 0);
    k++;
  }
  
  memset( ipad, 0, sizeof(ipad));
  memset( opad, 0, sizeof(opad));
  memcpy( ipad, key, 10);
  memcpy( opad, key, 10);

  // XOR with ipad and opad values
  int i;
  for (i = 0; i < 64; i++){
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  
  // Perform inner SHA1 
  sha1_init(&ctx);
  sha1_update(&ctx, ipad, 64);
  sha1_update(&ctx, data, sizeof(data));
  sha1_final(&ctx, digest);

  // Perform outer SHA1 
  sha1_init(&ctx);
  sha1_update(&ctx, opad, 64);
  sha1_update(&ctx, digest, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx, digest);
  
}
	

static int validateHOTP(char * secret_hex, char * HOTP_string){

  uint8_t hotp_digest[SHA1_DIGEST_LENGTH];
  // Create an 8 byte array for holding counter value : 0x 00 00 00 00 00 00 00 01
  unsigned char counter_text[8]; 
  unsigned long counter = 1;
  int i,j,k,last_byte;
  long dyn_trunc;
  long mod_value;
  char calculated_hotp_string[8]; // 6 values + '\0'
  calculated_hotp_string[8] = '\0';
 
  /*
  text[0] = (counter >> 56) & 0xFF; 
  text[1] = (counter >> 48) & 0xFF; 
  text[2] = (counter >> 40) & 0xFF; 
  text[3] = (counter >> 32) & 0xFF; 
  text[4] = (counter >> 24) & 0xFF; 
  text[5] = (counter >> 16) & 0xFF; 
  text[6] = (counter >> 8) & 0xFF; 
  text[7] = (counter) & 0xFF;
  --> Let's try doing it on a for loop 
  */
  for(j=0; j < sizeof(counter_text); j++){
    counter_text[j] = (counter >> (8 * (sizeof(counter_text) - (j+1) )) ) & 0xFF; 
  } 
 
  /* 
  for (k = 0; k < sizeof(text); k++){
    printf("%02x", text[k]);
  }
  
  printf("\n");
  */

  // stores final value onto hotp_digest  
  hmac_sha1(counter_text, sizeof(counter_text), secret_hex, strlen(secret_hex), hotp_digest); 
  
  /* 
  for (k = 0; k < sizeof(hotp_digest); k++){
    printf("%02x", hotp_digest[k]);
  }
  printf("\n");
  */

  // Get the offset value
  // This will give us where to get the 4 bytes from hotp_digest
  last_byte = (hotp_digest[sizeof(hotp_digest)-1] & 0x0F );
   
  // Make sure to remove the MSB of the 1st byte (0x7F)
  dyn_trunc = ((hotp_digest[last_byte] & 0x7F) << 24);
  dyn_trunc |= ((hotp_digest[last_byte+1] & 0xFF) << 16);
  dyn_trunc |= ((hotp_digest[last_byte+2] & 0xFF) << 8);
  dyn_trunc |= ((hotp_digest[last_byte+3] & 0xFF));

  mod_value = dyn_trunc % 1000000;
  snprintf(calculated_hotp_string, 7, "%d", mod_value);

  if(strncmp(calculated_hotp_string, HOTP_string, strlen(HOTP_string)) == 0) return 1;
  else return 0;
}

static int validateTOTP(char * secret_hex, char * TOTP_string){

  uint8_t totp_digest[SHA1_DIGEST_LENGTH];
  time_t curr_time = time(NULL);
  int T0 = 0;     
  int time_step = 30; // 30 seconds 
  unsigned long T = (curr_time - T0)/ time_step;
  uint8_t period[8];
  int j, last_byte;
  long dyn_trunc;
  long mod_value;
  char calculated_totp_string[8]; // 6 values + '\0'
  calculated_totp_string[8] = '\0';
 

  //printf("T: %d\n", T);

  for(j=0; j < sizeof(period); j++)
    period[j] = (T >> (8 * (sizeof(period) - (j+1) )) ) & 0xFF;  

 
  // stores final value onto totp_digest  
  hmac_sha1(period, sizeof(period), secret_hex, strlen(secret_hex), totp_digest); 
  /*
  printf("TOTP_DIGEST: ");
  int n;
  for(n=0; n < sizeof(totp_digest); n++)
    printf("%02x", totp_digest[n]);
 
  printf("\n");
  */
  // Get the offset value
  // This will give us where to get the 4 bytes from hotp_digest
  last_byte = (totp_digest[sizeof(totp_digest)-1] & 0x0F );
   
  // Make sure to remove the MSB of the 1st byte (0x7F)
  dyn_trunc = ((totp_digest[last_byte] & 0x7F) << 24);
  dyn_trunc |= ((totp_digest[last_byte+1] & 0xFF) << 16);
  dyn_trunc |= ((totp_digest[last_byte+2] & 0xFF) << 8);
  dyn_trunc |= ((totp_digest[last_byte+3] & 0xFF));

  mod_value = dyn_trunc % 1000000;
  snprintf(calculated_totp_string, 7, "%d", mod_value);

  //printf("Calculated TOTP string: %s\n", calculated_totp_string);

  if(strncmp(calculated_totp_string, TOTP_string, strlen(TOTP_string)) == 0) return 1;
  else return 0;
}

int main(int argc, char * argv[]){
  if ( argc != 4 ) {
    printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
    return(-1);
  }

  char * secret_hex = argv[1];
  char * HOTP_value = argv[2];
  char * TOTP_value = argv[3];
  int len = strlen(secret_hex);

  assert (strlen(secret_hex) <= 20);
  assert (strlen(HOTP_value) == 6);
  assert (strlen(TOTP_value) == 6);
        
  
  printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n", secret_hex, 
    HOTP_value,
    validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
    TOTP_value,
    validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");
  
  return(0);
}
