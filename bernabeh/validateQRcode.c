#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"



static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	uint8_t  key_hex[SHA1_BLOCKSIZE]={0};
	uint8_t  key_ipad[SHA1_BLOCKSIZE]={0}; 
	uint8_t  key_opad[SHA1_BLOCKSIZE]={0}; 
	uint8_t	 sha_output[SHA1_DIGEST_LENGTH];
	uint8_t	 sha_output_tmp[SHA1_DIGEST_LENGTH];
	uint8_t  counter[8]={0};
	counter[7]=1;
	int key_len=20;//for SHA1
	int i,j=0;

	memcpy(key_hex,secret_hex,key_len);

	//convert ascii to hex
	for (i=0;i<key_len;i+=2){	
		key_hex[i]=key_hex[i]-0x30;
		key_hex[i+1]=key_hex[i+1]-0x30;
		key_hex[i]=key_hex[i]<<4|key_hex[i+1];
		key_hex[i/2]=key_hex[i];
		if(i!=0)
			key_hex[i]=0;
		key_hex[i+1]=0;
	}
	

	memcpy(key_ipad,key_hex,SHA1_BLOCKSIZE);
	memcpy(key_opad,key_hex,SHA1_BLOCKSIZE);

	//debug

	/*
	printf("hmac_result is \n" );
	for (i=0;i<SHA1_BLOCKSIZE;i++){	
		printf("%d: %x\n",i,key_ipad[i] );
	}
	*/


	for(i=0;i<SHA1_BLOCKSIZE;i++){
		key_ipad[i] ^= 0x36;
   		key_opad[i] ^= 0x5c;
	}



	SHA1_INFO ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, key_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, counter, 8);
	sha1_final(&ctx, sha_output_tmp);

	SHA1_INFO ctx2;
	sha1_init(&ctx2);
	sha1_update(&ctx2, key_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx2, sha_output_tmp, 20);
	sha1_final(&ctx2, sha_output);


	//HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
	//HMAC = H[(K XOR opad) || H((K XOR ipad) || C)]
	//HMAC-SHA-1(K,C)= SHA1[(K XOR opad) || SHA1((K XOR ipad) || C)]

	//from the rfc4226
	int offset = sha_output[19] & 0xf ;
	int bin_code = (sha_output[offset] & 0x7f) << 24
	| (sha_output[offset+1] & 0xff) << 16
	| (sha_output[offset+2] & 0xff) << 8
	| (sha_output[offset+3] & 0xff) ;

	int hotp_result=bin_code%(int)pow(10, 6);
	//printf("hotp_result is %d\n",hotp_result );

	if (hotp_result==atoi(HOTP_string))
		return 1;
	else
		return 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{

	uint8_t  key_hex[SHA1_BLOCKSIZE]={0};
	uint8_t  key_ipad[SHA1_BLOCKSIZE]={0}; 
	uint8_t  key_opad[SHA1_BLOCKSIZE]={0}; 
	uint8_t	 sha_output[SHA1_DIGEST_LENGTH];
	uint8_t	 sha_output_tmp[SHA1_DIGEST_LENGTH];
	uint8_t  time_counter[8]={0};
	uint8_t  ts=30;
	int key_len=20;//for SHA1
	int i,j=0;

	memcpy(key_hex,secret_hex,key_len);

	//convert ascii to hex
	for (i=0;i<key_len;i+=2){	
		key_hex[i]=key_hex[i]-0x30;
		key_hex[i+1]=key_hex[i+1]-0x30;
		key_hex[i]=key_hex[i]<<4|key_hex[i+1];
		key_hex[i/2]=key_hex[i];
		if(i!=0)
			key_hex[i]=0;
		key_hex[i+1]=0;
	}
	

	memcpy(key_ipad,key_hex,SHA1_BLOCKSIZE);
	memcpy(key_opad,key_hex,SHA1_BLOCKSIZE);

	//debug

	/*
	printf("hmac_result is \n" );
	for (i=0;i<SHA1_BLOCKSIZE;i++){	
		printf("%d: %x\n",i,key_ipad[i] );
	}
	*/


	for(i=0;i<SHA1_BLOCKSIZE;i++){
		key_ipad[i] ^= 0x36;
   		key_opad[i] ^= 0x5c;
	}

	// get current time
	time_t cur_time=time(NULL);
	unsigned long long big_t=cur_time/ts;
	//big_t=1111111109/30;
	/*
	time_counter[7]=big_t&0xFF;
	time_counter[6]=big_t>>8&0xFF;
	time_counter[5]=big_t>>8&0xFF;
	time_counter[4]=big_t>>8&0xFF;
	time_counter[3]=big_t>>8&0xFF;
	time_counter[2]=big_t>>8&0xFF;
	time_counter[1]=big_t>>8&0xFF;
	time_counter[0]=big_t>>8&0xFF;
	*/
	//printf(" big_t is %x\n",big_t );
	j=0;
	int offset_bits;
	for (i = 7; i > 0; i--)
	{
		offset_bits=8*j;
		time_counter[i]=(big_t>>offset_bits)&0xFF;
		//printf("offset_bits %d\n",offset_bits );
		j++;
	}

	for (i = 0; i < 8; i++)
	{	
		//printf("%x\n",time_counter[i] );
	}


	SHA1_INFO ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, key_ipad, SHA1_BLOCKSIZE);
	sha1_update(&ctx, time_counter, 8);
	sha1_final(&ctx, sha_output_tmp);

	SHA1_INFO ctx2;
	sha1_init(&ctx2);
	sha1_update(&ctx2, key_opad, SHA1_BLOCKSIZE);
	sha1_update(&ctx2, sha_output_tmp, 20);
	sha1_final(&ctx2, sha_output);


	//HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
	//HMAC = H[(K XOR opad) || H((K XOR ipad) || C)]
	//HMAC-SHA-1(K,C)= SHA1[(K XOR opad) || SHA1((K XOR ipad) || C)]

	//from the rfc4226
	int offset = sha_output[19] & 0xf ;
	int bin_code = (sha_output[offset] & 0x7f) << 24
	| (sha_output[offset+1] & 0xff) << 16
	| (sha_output[offset+2] & 0xff) << 8
	| (sha_output[offset+3] & 0xff) ;

	int totp_result=bin_code%(int)pow(10, 6);
	//printf("hotp_result is %d\n",hotp_result );

	if (totp_result==atoi(TOTP_string))
		return 1;
	else
		return 0;


}

int
main(int argc, char * argv[])
{
	//REMEMBER TO UNCOMMET THIESEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
	
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}
	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	
	//char *	secret_hex = "12345678901234567890";
	//char *	HOTP_value = "803282";
	//char *	TOTP_value = "139412";

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
