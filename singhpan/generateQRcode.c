#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
  if ( argc != 4 ) {
    printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
    return(-1);
  }

  char *issuer = argv[1];
  char *accountName = argv[2];
  char *secret_hex = argv[3];

  assert (strlen(secret_hex) <= 20);

  printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",issuer, accountName, secret_hex);

  // Create an otpauth:// URI and display a QR code that's compatible
  // with Google Authenticator

  //convert secret form number string to uint8_t array
  char padded_hex[20];
  char *buf = malloc(40+strlen(issuer)+strlen(accountName)+20);
  uint8_t *data = malloc(20*sizeof(uint8_t));
  uint8_t *result = malloc(20*sizeof(uint8_t));
  memset(result, 0, (size_t)20);
  memset(data, 0, (size_t)20);
  
  int i;
  int pad_len = 20 - strlen(secret_hex);
  for(i = 0; i<pad_len; i++){
    padded_hex[i] = 0;
  }
  for(i = pad_len; i<20; i++){
    padded_hex[i] = secret_hex[i-pad_len];
  }
  padded_hex[i] = '\0';

  for(i = 0; i< strlen(padded_hex); i++){

    switch(padded_hex[i]){
    case '0':
      data[i] = 0;
      break;
    case '1':
      data[i] = 1;
      break;
    case '2':
      data[i] = 2;
      break;
    case '3':
      data[i] = 3;
      break;
    case '4':
      data[i] = 4;
      break;
    case '5':
      data[i] = 5;
      break;
    case '6':
      data[i] = 6;
      break;
    case '7':
      data[i] = 7;
      break;
    case '8':
      data[i] = 8;
      break;
    case '9':
      data[i] = 9;
      break;
    case 'A':
      data[i] = 10;
      break;
    case 'B':
      data[i] = 11;
      break;
    case 'C':
      data[i] = 12;
      break;
    case 'D':
      data[i] = 13;
      break;
    case 'E': 
      data[i] = 14;
      break;
    case 'F':
      data[i] = 15;
      
    }
  }
  data[i] = '\0';
  
  int len = strlen(padded_hex)/2;
  int j = 0;
  for(i = 0; i<len; i++){
    data[i] = (data[j]<<4)|data[j+1];
    j = j+2;
  }
  data[len] = 0;
  
  base32_encode(data, 10, result, 80); 
  
  const char *name_encoded = urlEncode(accountName);
  const char *issuer_encoded = urlEncode(issuer);
  
  memset(buf, 0, sizeof(buf));
  sprintf(buf, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1\n", name_encoded, issuer_encoded, result);
  displayQRcode(buf);

  memset(buf, 0, sizeof(buf));
  sprintf(buf, "otpauth://totp/%s?issuer=%s&secret=%s&period=30\n", name_encoded, issuer_encoded, result);
  displayQRcode(buf);
  
  return (0);
}
