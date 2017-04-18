#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "lib/encoding.h"


/* Basically convert the char '0' -> 0
 * Our value of '0' is 48 (in decimal). We actually want 0 (in decimal).
 * So, we subtract the decimal value of '0' (which is 48) from 48, which results in decimal value of 0.
 * For, 'a' to 'f' our decimal values are 97-102. But, we want decimal value range 10-15. 
 * Thus, we subtract those values from 97 and add 10. We do the same for the range 'A' to 'F'.
 */
int char_to_int(char c){
  if(c >= '0' && c <= '9') return c - 48;
  if(c >= 'a' && c <= 'f') return c - 97 + 10;
  if(c >= 'A' && c <= 'F') return c - 65 + 10;
  return -1;
}

/* Once we get the int value of the hex, we convert it into decimal in order to get ASCII text (using %c format).
 * We do that by taking the powers of 16. 
 * For example, 12 (Hex) -> (1 x 16^1) + (2 x 16^0) = 18 (dec). Then, we can use %c format to convert 18 to ASCII
 */
char hex_to_decimal(char c, char d){
  int msb = char_to_int(c) * pow(16, 1);
  int lsb = char_to_int(d) * pow(16, 0);
  return (char) msb+lsb;
}

int main(int argc, char * argv[]){
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];
        size_t len = strlen(secret_hex);

        char * encoded_secret = (char *) malloc (10);
        
	assert ((len) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	
        const char * encoded_account_name = urlEncode(accountName); 
        const char * encoded_issuer = urlEncode(issuer);

        char val[10];
        char buf = 0;
        int i;
        int j = 0;
        for(i = 0; i < len; i++){
          if(i % 2 != 0){
            char ch = hex_to_decimal(buf, secret_hex[i]);
            val[j] = ch;
            j++;
          }else{
            buf = secret_hex[i];
          }
        }
        val[10] = '\0';

        char * final_secret = val;

        int num_enc_secret = base32_encode(final_secret, 10, encoded_secret, 200); 
        
        char hotp_url[1024];
        sprintf(hotp_url, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_account_name, encoded_issuer, encoded_secret);	
        hotp_url[strlen(hotp_url)] = '\0';

        displayQRcode(hotp_url);

        char totp_url[1024];
        sprintf(totp_url, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_account_name, encoded_issuer, encoded_secret);
        totp_url[strlen(totp_url)] = '\0';

        displayQRcode(totp_url);

        return (0);
}
