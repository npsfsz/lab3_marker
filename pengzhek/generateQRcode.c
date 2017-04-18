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

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);
   
    char secret[20]="";
    char * secretpd=secret_hex;
    int i,j=0;
    
    //padding
    if(strlen(secret_hex)<20){
    	for(i=0;i<strlen(secret_hex);i=i++){
            secret[i]=secret_hex[i];
    	}
    	for(j=strlen(secret_hex);j<20;j++){
    		secret[j]='0';
    	}
      secret[20] = '\0';
      strcpy(secretpd,secret);
    } 
    
    //printf("here\n");

    //UTF8-Transform
    int h,l; //high byte & lower byte
    int trans[10];
    char secrettrans[20]="";
    j=0; 
    for(i=0;i<20;i++){
      //0-9
      if(secretpd[i]<=57){
      	if(i%2==0)
      	h=secretpd[i]-48;
        else
        l=secretpd[i]-48;
      }
      
      //A-F
      else if(secretpd[i]>=65 && secretpd[i]<=70){
      	if(i%2==0)
      	h=secretpd[i]-65+10;
        else
        l=secretpd[i]-65+10;	
      }
      	
      //a-f
	  else if(secretpd[i]>=97 && secretpd[i]<=102){
	  	if(i%2==0)
	  		h=secretpd[i]-97+10;
	  	else 
	  		l=secretpd[i]-97+10;
	  }
     //save 
      if(i%2!=0){
      	trans[j]=h*16+l;
        secrettrans[j]=(char)trans[j];
        j++;
      }
    }
    

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
       char result[20];
       base32_encode((const uint8_t *)secrettrans,10,result,16);
      // printf(result);
       
       //encode accountname and issuer
       const char * enaccountname=urlEncode(accountName);
       const char * enissuer=urlEncode(issuer);
       
       char ot1[100]; 
       char ot2[100];
       sprintf(ot1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", enaccountname, enissuer, result);
       displayQRcode(ot1);
       sprintf(ot2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", enaccountname, enissuer, result);
       displayQRcode(ot2);




	//displayQRcode("otpauth://testing");

	return (0);
}
