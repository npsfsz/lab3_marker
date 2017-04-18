#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h> 

#include "lib/encoding.h"

//function to pad secret(more) to 20 characters
void paddingfunctionMore(char *secret, char *updatedSecret/*, int extraLen*/)
{
	int counter=0;

		
	while(counter<21){	//copy the secret into a updated secret 
		updatedSecret[counter]=secret[counter];
		 counter++;
	}
return;
}

//function to pad secret(less) to 20 characters
void paddingfunctionLess(char *secret, char *updatedSecret, int requiredLen)
{
	int counter=0;
	int countCheck=0;
	int countCheckResult=0;
	while(secret[counter]!='\0'){	//copy the secret into a updated secret 
		updatedSecret[counter]=secret[counter];
		 counter++;
	}
	countCheck=counter;
	countCheckResult=20-countCheck;
	//counter =counter-1;
	
	if(countCheckResult!=requiredLen){
		printf("INCORRECT");
	}
	
	while(counter<21){		//to make up the 20 characters. pad the remaining with '0'
		updatedSecret[counter]= '0';
		counter++;
	}
return;	
}

//function to copy string
void copyfunction(char *secret, char *updatedSecret)
{
	int counter=0;
	while(secret[counter]!='\0'){
		updatedSecret[counter]=secret[counter];
		counter++;
	}
return;
}

//-------------------------------------------------------------------------------------

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

	//----------------------------------------------------------------------------------
		
	uint8_t finalSecret[20];	

	//getting Account Name and issuer
	char finalAccountName[100];
	char finalIssuer[100];
	

	//char Eacc=urlEncode(accountName);
	//char Eiss=urlEncode(issuer)

	//copyfuntion(finalAccountName,Eacc); //encoding the account name
	//copyfunction(finalIssuer, Eiss); //encoding the issuer
	
	strcpy(finalAccountName,urlEncode(accountName));
	strcpy(finalIssuer,urlEncode(issuer));



	//printf("Encoded account name: %s\n", finalAccountName);
	//printf("Encoded issuer: %s\n", finalIssuer);
	
	
	//getting and padding the hex secret to 20 characters
	
	int counter=0;
	int secretCount=0;
	bool secretCheck;
	char updatedSecret[20];
	
	secretCount = strlen(secret_hex);
	if(secretCount<20){      //If secret is less than 20 characters
		printf("less than 20");
		int requiredLen=0;
		requiredLen=20-secretCount;
		
		paddingfunctionLess(secret_hex,updatedSecret,requiredLen);
		printf("hex_secret:      \"%s\"\n", secret_hex);
		printf("updated secret:      \"%s\"\n", updatedSecret);
		
		
		
		int secretCount1 = strlen(updatedSecret);
		if(secretCount1==20){
		secretCheck=true;
		}
	
	}
	
	else if(secretCount>20){	//If secret is more than 20 characters
		printf("more than 20");
		int extraLen=0;
		extraLen=secretCount-20;
		
		paddingfunctionMore(secret_hex,updatedSecret);
		printf("hex_secret:      \"%s\"\n", secret_hex);
		printf("updated secret:      \"%s\"\n", updatedSecret);
		
		int secretCount1 = strlen(updatedSecret);
		if(secretCount1==20){
		secretCheck=true;
		}


	}
	
	else if(secretCount==20){	//if secret is exactly 20 characters
		//printf("exactly 20");
		copyfunction(secret_hex,updatedSecret);
		
		secretCheck=true;
	}
	
	
	
	if(secretCheck==true){	//if the secret is 20 characters
	
	uint8_t myByteArray[10];
	int i=0;
    for (i = 0; i < 10; i++) //byte array is 20. divide by 2 is 10.
    {
        sscanf(updatedSecret + 2*i, "%02x", &myByteArray[i]);       
    }
	




	int count;
   	count = base32_encode(myByteArray,10,finalSecret,20);
	
	}
	else{
		printf("ERROR, updated secret not 20 characters!");
		return;
	}
		
		
		
		
		
		
	//----------------------------------------------------------------------------------
		
	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator

	//displayQRcode("otpauth://testing");

	
	char a1[200];
	char a2[200];
	
	
	//char * auf1 = (char*) malloc(100);
	sprintf(a1/*,buf1*/, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", finalAccountName, finalIssuer, finalSecret);
	//char * auf2 = (char*) malloc(100);
	sprintf(a2/*,buf2*/, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", finalAccountName, finalIssuer, finalSecret);
	
	displayQRcode(a1);
	displayQRcode(a2);
	
	//free(auf1);
	//free(auf2);
	
	return (0);
}
