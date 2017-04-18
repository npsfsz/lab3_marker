#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/encoding.h"

#define SECRET_LENGTH 20
#define URI_BASE_LENGTH 43    /* 42 + NULL */
#define BASE_32_SECRET_LEN 17 /* 16 + NULL */

enum uri_type { HOTP_URI, TOTP_URI };

/**
 * Convert a hex string to its byte value.
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
 * Encode the secret string properly for the uri.
 */
char *uri_encode_secret(char *secret) {
  int len = strlen(secret);
  uint8_t *result = malloc(BASE_32_SECRET_LEN);
  uint8_t *data = malloc(len / 2);

  data = hex_decode(secret, len, data);
  base32_encode(data, len / 2, result, BASE_32_SECRET_LEN);
  free(data);

  return (char *)result;
}

/**
 * Generate a uri of the requested type for given issuer/account/secret.
 */
char *generate_uri(enum uri_type type, char *issuer, char *account_name,
                   char *secret_hex) {
  const char *uri_encoded_issuer = urlEncode(issuer);
  const char *uri_encoded_account = urlEncode(account_name);
  char *uri_encoded_secret = uri_encode_secret(secret_hex);
  int result_len = URI_BASE_LENGTH + strlen(uri_encoded_issuer) +
                   strlen(uri_encoded_account) + strlen(uri_encoded_secret);
  char *result = malloc(result_len);

  if (type == HOTP_URI) {
    sprintf(result, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",
            uri_encoded_account, uri_encoded_issuer, uri_encoded_secret);
  } else {
    sprintf(result, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",
            uri_encoded_account, uri_encoded_issuer, uri_encoded_secret);
  }

  free(uri_encoded_secret);
  return result;
}

/**
 * Main
 */
int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
    return (-1);
  }

  char *issuer = argv[1];
  char *accountName = argv[2];
  char *secret_hex = argv[3];
  char *hotp_uri_buf;
  char *totp_uri_buf;

  assert(strlen(secret_hex) <= SECRET_LENGTH);
  printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n", issuer,
         accountName, secret_hex);

  hotp_uri_buf = generate_uri(HOTP_URI, issuer, accountName, secret_hex);
  totp_uri_buf = generate_uri(TOTP_URI, issuer, accountName, secret_hex);

  displayQRcode(hotp_uri_buf);
  displayQRcode(totp_uri_buf);

  free(hotp_uri_buf);
  free(totp_uri_buf);
  return (0);
}
