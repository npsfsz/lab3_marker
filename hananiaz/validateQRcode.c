#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>

#include "lib/sha1.h"

uint8_t to_hex(char c) {
  if(c >= '0' && c <= '9') {
  	return (c - '0');
  } else if(c >= 'a' && c <= 'f') {
		return (c - 'a' + 10);
	} else if (c >= 'A' && c <= 'F') {
		return (c - 'A' + 10);
	} else {
		return ('0');
	}
}

int
validateHOTP(char * secret_hex, char * HOTP_string)
{
  int i;
  long movingFactor = 1;
  uint8_t text[8];
    for( i = 7; i >= 0 ; i--){
    text[i] = (char)(movingFactor & 0xff);
    movingFactor >>= 8;
  }

  uint8_t ipad[SHA1_BLOCKSIZE];
  memset(ipad, 0, SHA1_BLOCKSIZE);

  uint8_t opad[SHA1_BLOCKSIZE];
  memset(opad, 0, SHA1_BLOCKSIZE);

  // Key length = 10
  uint8_t key[10];

  int j = 0;
  for (i = 0; i < 20; i += 2) {
  	key[j] = to_hex(secret_hex[i]) * 16 + to_hex(secret_hex[i + 1]);
  	j++;
  }
  
  memcpy(ipad, key, 10);
  memcpy(opad, key, 10);

  for (i = 0; i < SHA1_BLOCKSIZE; i++) {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
  }

  // Compute inner hmac hash
  SHA1_INFO ctx_inner;
  uint8_t ihmac[SHA1_DIGEST_LENGTH];
  sha1_init(&ctx_inner);
  sha1_update(&ctx_inner, ipad, SHA1_BLOCKSIZE);
  sha1_update(&ctx_inner, text, 8);
  sha1_final(&ctx_inner, ihmac);

  // Compute outer hmac hash
  SHA1_INFO ctx_outer;
  uint8_t hmac[SHA1_DIGEST_LENGTH];
  sha1_init(&ctx_outer);
  sha1_update(&ctx_outer, opad, SHA1_BLOCKSIZE);
  sha1_update(&ctx_outer, ihmac, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx_outer, hmac);

  int offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0x0f;
  long binary = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | ( hmac[offset + 3] & 0xff);

  // Check if valid
	return (binary % 1000000 == atoi(HOTP_string));
}

int
validateTOTP(char * secret_hex, char * TOTP_string)
{
  int i;
  int period = ((int)time(NULL))/30;
  uint8_t timer[8]; 
  for( i = 7; i >= 0 ; i--){
      timer[i] = period & 0xff;
      period >>= 8;
  }
  
  uint8_t ipad[SHA1_BLOCKSIZE];
  memset(ipad, 0, SHA1_BLOCKSIZE);

  uint8_t opad[SHA1_BLOCKSIZE];
  memset(opad, 0, SHA1_BLOCKSIZE);

  // Key length = 10
  uint8_t key[10];

  int j = 0;
  for (i = 0; i < 20; i += 2) {
  	key[j] = to_hex(secret_hex[i]) * 16 + to_hex(secret_hex[i + 1]);
  	j++;
  }
  
  memcpy(ipad, key, 10);
  memcpy(opad, key, 10);

  for (i = 0; i < SHA1_BLOCKSIZE; i++) {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
  }

	// Compute inner hmac hash
  SHA1_INFO ctx_inner;
  uint8_t ihmac[SHA1_DIGEST_LENGTH];
  sha1_init(&ctx_inner);
  sha1_update(&ctx_inner, ipad, SHA1_BLOCKSIZE);
  sha1_update(&ctx_inner, timer, 8);
  sha1_final(&ctx_inner, ihmac);

	// Compute outer hmac hash
  SHA1_INFO ctx_outer;
  uint8_t hmac[SHA1_DIGEST_LENGTH];
  sha1_init(&ctx_outer);
  sha1_update(&ctx_outer, opad, SHA1_BLOCKSIZE);
  sha1_update(&ctx_outer, ihmac, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx_outer, hmac);

  int offset = hmac[SHA1_DIGEST_LENGTH - 1] & 0x0f;
  long binary = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | ( hmac[offset + 3] & 0xff);

  // Check if valid
	return (binary % 1000000 == atoi(TOTP_string));
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

	// Make sure secret is padded with zeros if less than 20
	char padded_secret[21];
	int i;

	for (i = 0; i < strlen(secret_hex); i++) {
		padded_secret[i] = secret_hex[i];
	}

	for (i  =strlen(secret_hex); i < 20; i++) {
		padded_secret[i] = '0';
	}

	// Terminate with null char
	padded_secret[20] = '\0';

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(padded_secret, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(padded_secret, TOTP_value) ? "valid" : "invalid");

	return(0);
}
