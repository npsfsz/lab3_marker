#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#define SECRET_SIZE_IN_BIT 80
#define SECRET_SIZE_IN_HEX 20
#define SECRET_SIZE_IN_BYTE 10
#define SECRET_SIZE_IN_BASE32 16

int char_to_int(char c) {
    int result = 0;  // so the unexpected char will have value of 0
    if (c >= '0' && c <= '9')
        result = c - '0';
    else if (c >= 'A' && c <= 'F')
        result = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
        result = c - 'a' + 10;
    
    return result;
}


int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

        /** encode accountname and issuer */
        char *	encoded_issuer = urlEncode(issuer);
	char *	encoded_accountName = urlEncode(accountName);
        
        /** encode secret */
        // pad with zero at the end if the size smaller than 20
        int secret_hex_complete[SECRET_SIZE_IN_HEX + 1];
        secret_hex_complete[SECRET_SIZE_IN_HEX] = '\0';
        
        int secret_input_len = strlen(secret_hex);
        int i = 0;
        for (; i < secret_input_len; i++){
            secret_hex_complete[i] = secret_hex[i];
        }
  
        
        if (secret_input_len < SECRET_SIZE_IN_HEX){
            for (i = secret_input_len; i < SECRET_SIZE_IN_HEX; i++){
                secret_hex_complete[i] = '\0';
            }  
        }
        
        
        // convert hex to byte
        uint8_t secret_in_byte[SECRET_SIZE_IN_BYTE + 1];
        secret_in_byte[SECRET_SIZE_IN_BYTE] = '\0';
        
        for (i = 0; i < SECRET_SIZE_IN_BYTE; i++){
            char left_hex = secret_hex_complete[i * 2];
            char right_hex = secret_hex_complete[i * 2 + 1];
            
            secret_in_byte[i] = char_to_int(left_hex) * 16 + char_to_int(right_hex);
        }
        
        uint8_t secret_hex_base32[SECRET_SIZE_IN_BASE32 + 1];
        secret_hex_base32[SECRET_SIZE_IN_BASE32] = '\0';
        base32_encode(secret_in_byte, SECRET_SIZE_IN_BYTE, secret_hex_base32, SECRET_SIZE_IN_BASE32);
        
        
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
        int output_len = SECRET_SIZE_IN_BASE32 + strlen(encoded_issuer) + strlen(encoded_accountName) + 150;
        
        char hotp_code[output_len];
        memset(hotp_code, '\0', sizeof(hotp_code));
	sprintf(hotp_code, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encoded_accountName, encoded_issuer, secret_hex_base32);
	displayQRcode(hotp_code);

	char totp_code[output_len];
        memset(totp_code, '\0', sizeof(totp_code));
	sprintf(totp_code, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encoded_accountName, encoded_issuer, secret_hex_base32);
	displayQRcode(totp_code);


	return (0);
}
