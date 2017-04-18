#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include "lib/sha1.h"

int OTP_valid(char * secret_hex, unsigned char * data, char * HOTP_string);
unsigned char strToHex(char c);

int
validateHOTP(char * secret_hex, char * HOTP_string)
{

 long counter = 1; 
 unsigned char text[sizeof(counter)];

 int i; 
 for( i = sizeof(text)-1; i >= 0 ; i--){
    text[i] = (unsigned char)(counter & 0xff);
    counter >>= 8;  }

  return OTP_valid(secret_hex, text, HOTP_string);
}

int
validateTOTP(char * secret_hex, char * TOTP_string)
{
  unsigned char timer[8]; 
  int time_limit;
 
  time_limit = ((int)time(NULL))/30; // period = 30

  int i;
  for( i = 7; i >= 0 ; i--){
    timer[i] = (unsigned char) (time_limit & 0xff);
    time_limit >>= 8;  }

  return OTP_valid(secret_hex, timer, TOTP_string);
}

int
main(int argc, char * argv[])
{
  if ( argc != 4 ) {
    printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
    return(-1);  }

  char *secret_hex = argv[1];
  char *HOTP_value = argv[2];
  char *TOTP_value = argv[3];

  assert (strlen(secret_hex) <= 20);
  assert (strlen(HOTP_value) == 6);
  assert (strlen(TOTP_value) == 6);

  printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
	 secret_hex, HOTP_value,
	 validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
	 TOTP_value,
	 validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

  return(0);
}

int
OTP_valid(char * secret_hex, unsigned char * data, char * HOTP_string)
{
    long otp;
    char otp_str[7];
    int offset;
    long binary;
    SHA1_INFO ctx;
    unsigned char ipad[65]; /* inner padding */
    unsigned char opad[65]; /* outer padding */

    size_t string_length;
    string_length = strlen(secret_hex);
    size_t key_length;
    key_length = string_length / 2;
    unsigned char key[key_length];

    /* Convert string of 20 hex characters to an array of bytes */
    int i, j;
    for (i = 0, j = 0; i < string_length; i+=2, j++)
        key[j] = (unsigned char) (strToHex(secret_hex[i]) * 16 + strToHex(secret_hex[i + 1]));

    memset(ipad, 0, sizeof(ipad));
    memcpy(ipad, key, key_length);
    memset(opad, 0, sizeof(opad));
    memcpy(opad, key, key_length);

    /* XOR inner padding and outer padding values with key */
    for (i = 0; i < 64; i++) {  ipad[i] ^= 0x36;    opad[i] ^= 0x5c; }

    // Compute hash
    unsigned char ihmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, data, sizeof(data));
    sha1_final(&ctx, ihmac);

    // Compute hash
    unsigned char hmac[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, ihmac, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, hmac);

    offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0x0f;
    binary = ((hmac[offset] & 0x7f) << 24)
             | ((hmac[offset + 1] & 0xff) << 16)
             | ((hmac[offset + 2] & 0xff) << 8)
             | ( hmac[offset + 3] & 0xff);

    otp = binary % 1000000;
    sprintf(otp_str, "%ld", otp);

    while(strlen(otp_str) < 6){
      char temp[7];
      temp[0]='0';
      strcat(temp, otp_str);
      strcpy(otp_str, temp);
    }
    if(strcmp(HOTP_string, otp_str)==0) return 1;
    else return 0;

}

unsigned char strToHex(char c) {
    if(c >= '0' && c <= '9') return (unsigned char)(c - '0');
    if(c >= 'a' && c <= 'f') return (unsigned char)(c - 'a' + 10);
    if(c >= 'A' && c <= 'F') return (unsigned char)(c - 'A' + 10);
}
