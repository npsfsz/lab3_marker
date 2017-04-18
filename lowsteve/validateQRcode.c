#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/sha1.h"

#define COUNTER_LENGTH 8 /* 8 byte moving factor */
#define DEFAULT_COUNTER_VALUE 1
#define TIME_STEP 30
#define DIGITS_POWER 1000000   /* 10^6 - i.e. output 6 digit codes */

/**
 * Converts a hex string to its byte value.
 */
uint8_t *hex_decode(const char *in, size_t len, uint8_t *out) {
  unsigned int i, t, hn, ln;

  for (t = 0, i = 0; i < len; i += 2, ++t) {
    hn = in[i] > '9' ? in[i] - 'A' + 10 : in[i] - '0';
    ln = in[i + 1] > '9' ? in[i + 1] - 'A' + 10 : in[i + 1] - '0';

    out[t] = (hn << 4) | ln;
  }

  return out;
}

/**
 * Convert an int into a byte array.
 */
void int_to_byte_array(int integer, uint8_t *array) {
  int i;
  for (i = COUNTER_LENGTH; i--; integer >>= 8) {
    array[i] = integer;
  }
}

/**
 * hmac_sha1 function implemented as per RFC 2104.
 */
void hmac_sha1(const uint8_t *key, int key_len, const uint8_t *data,
               int data_len, uint8_t *digest) {
  SHA1_INFO ctx;
  uint8_t key_xor_ipad[SHA1_BLOCKSIZE];
  uint8_t key_xor_opad[SHA1_BLOCKSIZE];
  int i;

  bzero(key_xor_ipad, sizeof(key_xor_ipad));
  bzero(key_xor_opad, sizeof(key_xor_opad));
  bcopy(key, key_xor_ipad, key_len);
  bcopy(key, key_xor_opad, key_len);
  for (i = 0; i < SHA1_BLOCKSIZE; i++) {
    key_xor_ipad[i] ^= 0x36;
    key_xor_opad[i] ^= 0x5c;
  }

  /* Inner hash */
  sha1_init(&ctx);
  sha1_update(&ctx, key_xor_ipad, SHA1_BLOCKSIZE);
  sha1_update(&ctx, data, data_len);
  sha1_final(&ctx, digest);

  /* Outer hash */
  sha1_init(&ctx);
  sha1_update(&ctx, key_xor_opad, SHA1_BLOCKSIZE);
  sha1_update(&ctx, digest, SHA1_DIGEST_LENGTH);
  sha1_final(&ctx, digest);
}

/**
 * Truncate the hmac to an OTP of the correct number of digits as per RFC 4226.
 */
int truncate(uint8_t *hmac) {
  int offset = hmac[19] & 0xf;
  int bin_code = (hmac[offset] & 0x7f) << 24
                  | (hmac[offset + 1] & 0xff) << 16
                  | (hmac[offset + 2] & 0xff) << 8
                  | (hmac[offset + 3] & 0xff);
  return (bin_code % DIGITS_POWER);
}

/**
 * Validate a HOTP.
 */
static int validateHOTP(char *secret_hex, char *HOTP_string, int count) {
  int secret_len = strlen(secret_hex);
  uint8_t *binary_secret = malloc(secret_len / 2);
  binary_secret = hex_decode(secret_hex, secret_len, binary_secret);

  uint8_t counter[COUNTER_LENGTH];
  int_to_byte_array(count, counter);

  uint8_t hmac[SHA1_DIGEST_LENGTH];
  hmac_sha1(binary_secret, secret_len / 2, counter, COUNTER_LENGTH, hmac);

  int computed_hotp = truncate(hmac);

  free(binary_secret);
  return (computed_hotp == atoi(HOTP_string));
}

/**
 * Validate a TOTP.
 */
static int validateTOTP(char *secret_hex, char *TOTP_string) {
  int curr_time = time(NULL) - 0; /* After 2038 int will be too small */
  int num_time_steps = curr_time / TIME_STEP;

  return validateHOTP(secret_hex, TOTP_string, num_time_steps);
}

/**
 * Main
 */
int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
    return (-1);
  }

  char *secret_hex = argv[1];
  char *HOTP_value = argv[2];
  char *TOTP_value = argv[3];

  assert(strlen(secret_hex) <= 20);
  assert(strlen(HOTP_value) == 6);
  assert(strlen(TOTP_value) == 6);

  printf(
      "\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
      secret_hex, HOTP_value,
      validateHOTP(secret_hex, HOTP_value, DEFAULT_COUNTER_VALUE) ? "valid"
                                                                  : "invalid",
      TOTP_value, validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

  return (0);
}
