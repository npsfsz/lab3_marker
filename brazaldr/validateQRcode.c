#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"

//counter size is 8 bytes according to page 5 in rfc4226
#define C_SIZE 8

unsigned int DT(uint8_t *hmac_result){
	int offset   =  hmac_result[19] & 0xf;
	int bin_code = (hmac_result[offset]  & 0x7f) << 24 |(hmac_result[offset+1] & 0xff) << 16 |(hmac_result[offset+2] & 0xff) <<  8 |(hmac_result[offset+3] & 0xff);

	return bin_code;
}

uint8_t charToHex(char p) {
	if (p >= '0' && p <= '9')
		return (p - '0');
	if (p >= 'A' && p <= 'F')
		return (p - 'A' + 10);
	
	// invalid character received
	return 1;
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	
	int first_cp_len = (int)(strlen(secret_hex)/2);//rounding down
	int second_cp_len = (int)(strlen(secret_hex)/2)+1;//rounding up
	unsigned char converted_hex[second_cp_len];
	char *p = secret_hex;
	unsigned char ticket[8];
	unsigned char sha_final[SHA1_DIGEST_LENGTH];
	unsigned char sha_interm[SHA1_DIGEST_LENGTH];
	SHA1_INFO ctx_first;
	SHA1_INFO ctx_second;
	unsigned char outter_xor[SHA1_BLOCKSIZE];
	unsigned char inner_xor[SHA1_BLOCKSIZE];
	unsigned char key[SHA1_BLOCKSIZE];
	
	// Convert the hex char's into proper byte array
	// Since there are 20 hex chars and each is represented by 4 bits, need 10 bytes
	// Need to take pairs of 4 bit characters and group them into single 8 bit element
	int i = 0;
	for (i = 0; i < first_cp_len; i++) {
		unsigned char val1, val2;
		val1 = charToHex(*p);
		val2 = charToHex(*(p+1));
		converted_hex[i] = ((val1 << 4) | val2); // Combine the 2 hex chars into single 8 bit values		
		//printf("converted hex is 0x%hx\n", converted_hex[i]);
		p = p + 2; // Go to the next 2 hex values
	}
	
	if(first_cp_len*2 == strlen(secret_hex)){//given secret hex has even number of digits
		
		// printf("even number\n");
		converted_hex[first_cp_len] = '\0';
		converted_hex[second_cp_len] = '\0';
		
	}else if(first_cp_len*2+1 == strlen(secret_hex)){//given secret hex has odd number of digits
		
		//todo: need to test for odd numbers
		// printf("odd number\n");
		unsigned char val1 = charToHex(*p);
		unsigned char val2 = charToHex('0');
		converted_hex[first_cp_len] = ((val1 << 4) | val2);;
		converted_hex[first_cp_len+1] = '\0';
	}
	
	//testing
	// for (i = 0; i < 12; i++) {
		// printf("converted hex is 0x%hx\n", converted_hex[i]);
	// }
	
	//set the ticket to be the first ticket
	for(i=0; i<C_SIZE; i++){
		
		if(i==C_SIZE-1){
			ticket[i] = 1;
		}else{
			ticket[i] = 0;
		}
		
	}

	for(i=0;i<SHA1_BLOCKSIZE;i++){
	
		if(i<strlen(converted_hex)){
			outter_xor[i] = 0x5c ^ converted_hex[i];
			inner_xor[i] = 0x36 ^ converted_hex[i];
		}else{
			outter_xor[i] = 0x5c ^ 0x00;
			inner_xor[i] = 0x36 ^ 0x00;
		}
	
	}
	
	//digest the first 
	sha1_init(&ctx_first);
	sha1_update(&ctx_first, inner_xor, SHA1_BLOCKSIZE);
	sha1_update(&ctx_first, ticket, C_SIZE);
	sha1_final(&ctx_first, sha_interm);

	//digest the second
	sha1_init(&ctx_second);
	sha1_update(&ctx_second, outter_xor, SHA1_BLOCKSIZE);
	sha1_update(&ctx_second, sha_interm, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx_second, sha_final);

    int D = DT(sha_final) % (int)(pow(10,6));

    if (D == atoi(HOTP_string)){
    	return 1;
    }else{
    	return 0;
	}
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	
	int first_cp_len = (int)(strlen(secret_hex)/2);//rounding down
	int second_cp_len = (int)(strlen(secret_hex)/2)+1;//rounding up
	unsigned char converted_hex[second_cp_len];
	char *p = secret_hex;
	unsigned char ticket[8];
	unsigned char sha_final[SHA1_DIGEST_LENGTH];
	unsigned char sha_interm[SHA1_DIGEST_LENGTH];
	SHA1_INFO ctx_first;
	SHA1_INFO ctx_second;
	unsigned char outter_xor[SHA1_BLOCKSIZE];
	unsigned char inner_xor[SHA1_BLOCKSIZE];
	unsigned char key[SHA1_BLOCKSIZE];
	
	// Convert the hex char's into proper byte array
	// Since there are 20 hex chars and each is represented by 4 bits, need 10 bytes
	// Need to take pairs of 4 bit characters and group them into single 8 bit element
	int i = 0;
	for (i = 0; i < first_cp_len; i++) {
		unsigned char val1, val2;
		val1 = charToHex(*p);
		val2 = charToHex(*(p+1));
		converted_hex[i] = ((val1 << 4) | val2); // Combine the 2 hex chars into single 8 bit values		
		//printf("converted hex is 0x%hx\n", converted_hex[i]);
		p = p + 2; // Go to the next 2 hex values
	}
	
	if(first_cp_len*2 == strlen(secret_hex)){//given secret hex has even number of digits
		
		// printf("even number\n");
		converted_hex[first_cp_len] = '\0';
		converted_hex[second_cp_len] = '\0';
		
	}else if(first_cp_len*2+1 == strlen(secret_hex)){//given secret hex has odd number of digits
		
		//todo: need to test for odd numbers
		// printf("odd number\n");
		unsigned char val1 = charToHex(*p);
		unsigned char val2 = charToHex('0');
		converted_hex[first_cp_len] = ((val1 << 4) | val2);;
		converted_hex[first_cp_len+1] = '\0';
	}
	
	//testing
	// for (i = 0; i < 12; i++) {
		// printf("converted hex is 0x%hx\n", converted_hex[i]);
	// }
	
	time_t t = time(NULL);
	//set the time to be the current time divided by 30 seconds
	for(i=0; i<C_SIZE; i++)
		ticket[i] = (unsigned char)((long)(t/30) >> (8*(C_SIZE-1-i)));
	


	for(i=0;i<SHA1_BLOCKSIZE;i++){
	
		if(i<strlen(converted_hex)){
			outter_xor[i] = 0x5c ^ converted_hex[i];
			inner_xor[i] = 0x36 ^ converted_hex[i];
		}else{
			outter_xor[i] = 0x5c ^ 0x00;
			inner_xor[i] = 0x36 ^ 0x00;
		}
	
	}
	
	//digest the first 
	sha1_init(&ctx_first);
	sha1_update(&ctx_first, inner_xor, SHA1_BLOCKSIZE);
	sha1_update(&ctx_first, ticket, C_SIZE);
	sha1_final(&ctx_first, sha_interm);

	//digest the second
	sha1_init(&ctx_second);
	sha1_update(&ctx_second, outter_xor, SHA1_BLOCKSIZE);
	sha1_update(&ctx_second, sha_interm, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx_second, sha_final);

    int D = DT(sha_final) % (int)(pow(10,6));

    if (D == atoi(TOTP_string)){
    	return 1;
    }else{
    	return 0;
	}
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

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
