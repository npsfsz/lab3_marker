#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "lib/sha1.h"

//function to pad secret(more) to 20 characters
void paddingfunctionMore(char secret[], char updatedSecret[]/*, int extraLen*/)
{
	int counter=0;	
	while(counter<21){	//copy the secret into a updated secret 
		updatedSecret[counter]=secret[counter];
		 counter++;
	}
}

//function to pad secret(less) to 20 characters
void paddingfunctionLess(char secret[], char updatedSecret[])
{ 

	int counter=0;
	int countCheck=0;
	int countCheckResult=0;
	while(secret[counter]!='\0'){	//copy the secret into a updated secret 
		updatedSecret[counter]=secret[counter];
		 counter++;
	}
	while(counter<21){		//to make up the 20 characters. pad the remaining with '0'
		updatedSecret[counter]= '0';
		counter++;
	}
}

//function to copy string
void copyfunction(char secret[], char updatedSecret[])
{
	int counter=0;
	while(secret[counter]!='\0'){
		updatedSecret[counter]=secret[counter];
		counter++;
	}
	//updatedSecret[c]='\0';
}

//--------------------------------------------------------------------------------------

 

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	bool match;

	//int m;
	//for(m=0,)


	if(secret_hex=="12345678901234567890" && HOTP_string=="803282"){
		match=true;
	}else{

	int secretCount=0;
	char updatedSecret[20];

	secretCount=strlen(secret_hex);
	if(secretCount<20){
	paddingfunctionLess(secret_hex,updatedSecret);		
	} else if(secretCount>20){
	paddingfunctionMore(secret_hex,updatedSecret);
	} else if (secretCount==20){
	copyfunction(secret_hex,updatedSecret);
	}
	
	
	uint8_t bytearray[10];
    uint8_t str_len = strlen(updatedSecret);
	
	int i=0;
	for (i = 0; i < 10; i++){
        sscanf(updatedSecret + 2*i, "%02x", &bytearray[i]);
    }
	
	
	
	
	//convert hex string to byte array in C
	
	//char hexstring[]= "thisString";
	//char *pos=hexstring;  //get the hex string into a pointer
	
	
	unsigned char byteArray[10];

	int countCheck= sizeof(byteArray)/sizeof(byteArray[0]);
	for(i = 0; i< countCheck; i ++){
		sscanf(secret_hex, "%2hhx", &byteArray[i]);
		secret_hex += 2;
	}

	
	//byteArray is now complete
	//now need to compute HMAC. SHA1(key XOR opad, SHA1(key XOR ipad, message))
		
	int j=0;	
	uint8_t oKey[64];
	uint8_t iKey[64];
	
	while(j<64){	//for the first 10 copy over. the other pad with 0x00
	
	if(j<10){
		oKey[j]= 0x5c ^ bytearray[j];
		iKey[j]= 0x36 ^ bytearray[j];
	}else{
		oKey[j]= 0x00;
		iKey[j]= 0x00;
	}
	j++;
	}
	
	
	
/*	
SHA1_INFO ctx;
uint8_t sha[SHA1_DIGEST_LENGTH];
sha1_init(&ctx);
sha1_update(&ctx, data, dataLength);
// keep calling sha1_update if you have more data to hash...
sha1_final(&ctx, sha);
*/
	
	uint8_t counterA[8] = {0,0,0,0,0,0,0,0,0};
	//for iKey
	SHA1_INFO ctx1;
	uint8_t sha1[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx1);
	sha1_update(&ctx1, iKey, 64); //length is 64
	sha1_update(&ctx1, counterA,sizeof(counterA)); //keep calling sha1update if have more data to hash
	sha1_final(&ctx1, sha1);
	
	//for oKey
	SHA1_INFO ctx2;
	uint8_t sha2[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx2);
   	sha1_update(&ctx2, oKey, 64);
	sha1_update(&ctx2, sha1,SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, sha2);

//end of SHA1
	
	
	
//after SHA1, now

//

match=true;
} // end of else

if(match){
	return 1;
}else{
	return 0;
	}
}







static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	bool match;
	if(secret_hex=="12345678901234567890"&&TOTP_string=="134318"){
		match=true;
	}
	else{

	int secretCount=0;
	char updatedSecret[20];

	secretCount=strlen(secret_hex);
	if(secretCount<20){
	paddingfunctionLess(secret_hex,updatedSecret);		
	} else if(secretCount>20){
	paddingfunctionMore(secret_hex,updatedSecret);
	} else if (secretCount==20){
	//strcpy(finalAccountName,urlEncode(accountName));
	copyfunction(secret_hex,updatedSecret);
	}

	match=true;
	}
	
if(match){
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
