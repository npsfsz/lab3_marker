#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define SECRET_HEX_LEN 20
#define NUM_SECRET_BYTES 10
#define MAX_URI_LEN 300
int main(int argc, char *argv[])
{
  if (argc != 4)
  {
    printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
    return (-1);
  }

  char hotpUri[MAX_URI_LEN];
  char totpUri[MAX_URI_LEN];

  char *issuer = argv[1];
  char *accountName = argv[2];
  char *secret_hex = argv[3];

  char padded_secret[SECRET_HEX_LEN];
  int len = strlen(secret_hex);
  assert(len <= SECRET_HEX_LEN);

  int i = 0;
  for (i = 0; i < len; i++)
  {
    padded_secret[i] = secret_hex[i];
  }

  //if its less than 20 than pad rest with zeroes
  if (len <= SECRET_HEX_LEN)
  {
    int padding_len = SECRET_HEX_LEN - len;

    for (i = len; i < SECRET_HEX_LEN; i++)
    {
      padded_secret[i] = '0';
    }
  }

  //convert hexidecimal representation to a byte array 20 hex digits/2= 10 bytes

  uint8_t byte_arr[NUM_SECRET_BYTES];
  for (i = 0; i < NUM_SECRET_BYTES; i++)
  {
    sscanf(&padded_secret[2 * i], "%02x", &byte_arr[i]);
  }
  //DEBUG
  /*printf("byte array is:");
  for (i = 0; i < NUM_SECRET_BYTES; i++)
  {
    printf("%02x", byte_arr[i]);
  }
  printf("\n");*/

  //Base 32 allows to encode every 5 bits using a single character. So roughly to contain encoding 2 times should be a safe approx
  uint8_t encoded_secret[2 * NUM_SECRET_BYTES];
  int len_encode = base32_encode(byte_arr, NUM_SECRET_BYTES, encoded_secret, 2 * NUM_SECRET_BYTES);

  //DEBUG
 /* printf("encoded secret is:");
  for (i = 0; i < 2 * NUM_SECRET_BYTES; i++)
  {
    printf("%02x", encoded_secret[i]);
  }
  printf("\n");*/

  /*printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
         issuer, accountName, secret_hex);*/
  snprintf(hotpUri, MAX_URI_LEN, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", urlEncode(accountName), urlEncode(issuer), encoded_secret);
  displayQRcode(hotpUri);

  sprintf(totpUri, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", urlEncode(accountName), urlEncode(issuer), encoded_secret);
  displayQRcode(totpUri);

  // Create an otpauth:// URI and display a QR code that's compatible
  // with Google Authenticator

  //displayQRcode("otpauth://testing");

  return (0);
}
