#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#define MOVING_FACTOR 1
#define TIME 30
#define V1 0x36
#define V2 0x5c

void get_hmac(uint8_t* secret_hex, uint8_t* message, uint8_t out[20]) {

  // Lecture: HMAC = H[(K ⊕ opad) || H((K ⊕ ipad) || M)]

  uint8_t in_uint[strlen(secret_hex)/2];
  int i;

  // Convert the hex string to binary
  for (i=0;i*2<strlen(secret_hex);i++) {
    char curr[3];
    curr[0] = secret_hex[i*2];
    curr[1] = secret_hex[i*2+1];
    curr[2] = '\0';
    in_uint[i] = strtol(curr,NULL,16);
  }       

  // Xor with 0x36 and 0x5c to get two keys
  uint8_t p1[65];
  uint8_t p2[65];
  for (i=0; i<64; i++) {
    if (i < (strlen(secret_hex)/2)) { 
      p1[i] = in_uint[i]^V1;
      p2[i] = in_uint[i]^V2;
    } else {
      p1[i] = V1;
      p2[i] = V2;
    }
  }

  // Hash the message with
  SHA1_INFO ctx1;
  SHA1_INFO ctx2;
  uint8_t   shai[20];
  sha1_init(&ctx1);
  sha1_init(&ctx2);
  sha1_update(&ctx1, p1, 64);
  sha1_update(&ctx2, p2, 64);

  sha1_update(&ctx1, message, sizeof(message));
  sha1_final(&ctx1, shai);
  sha1_update(&ctx2, shai,20);
  sha1_final(&ctx2, out);
  
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
  // Get 'moving factor' (based on documentation provided)
  long movingFactor = MOVING_FACTOR;
  uint8_t text[sizeof(movingFactor)];
  int i;
  for (i = sizeof(movingFactor) - 1; i >= 0; i--) {
       text[i] = (movingFactor & 0xff);
       movingFactor >>= 8;
   }
  
  // Compute the hmac
  uint8_t sha[20];
  get_hmac(secret_hex, text, sha);

  // Change to 6 digits (based on documentation provided)
  int offset = sha[19] & 0xf;
  int bin_code = (sha[offset] & 0x7f) << 24
      | (sha[offset+1] & 0xff) << 16
      | (sha[offset+2] & 0xff) << 8
      | (sha[offset+3] & 0xff) ;
  bin_code = bin_code % 1000000;

  // Compare with HOTP_string
  int HOTP_bin = strtol(HOTP_string,NULL,10);
  if (bin_code == HOTP_bin)
    return 1;
  else 
    return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{ 
  // the time value should be the same if the TOTP_string
  // was defined and validated within 30 seconds. 
  long unsigned int time_val = time(NULL)/TIME; 
  int i;
  uint8_t time_shifted[8];
  for( i = 0; i < 8 ; i++){
    time_shifted[i] = (time_val >> 8*(7-i));
  }
    
  // Compute the hmac
  uint8_t sha[20];
  get_hmac(secret_hex, time_shifted, sha);
 
  // Change to 6 digits (based on documentation provided)
  int offset = sha[19] & 0xf;
  int bin_code = (sha[offset] & 0x7f) << 24
      | (sha[offset+1] & 0xff) << 16
      | (sha[offset+2] & 0xff) << 8
      | (sha[offset+3] & 0xff) ;
  bin_code = bin_code % 1000000;

  // Compare with HOTP_string
  int TOTP_bin = strtol(TOTP_string,NULL,10);
  if (bin_code == TOTP_bin)
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
       
        // Padd secret to 20 bytes
	char* secret_20char = (char*) (malloc(100));
        strcpy(secret_20char, secret_hex);
        int i;
        for (i = strlen(secret_hex); i < 20; i++) {
	  secret_20char[i] = '0';
	}
        secret_20char[20]='\0';

	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

        int y;

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_20char, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
	       validateTOTP(secret_20char, TOTP_value) ? "valid" : "invalid");

	return(0);
}
