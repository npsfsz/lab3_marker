#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lib/sha1.h"

void toBinary (char* secret_hex, uint8_t* byteArray)
{
    int i;
    unsigned int numBytes = strlen(secret_hex)/ 2;
    char* pos = secret_hex;
    for (i = 0; i < numBytes; i++) //1 byte = 2 hex
    {
        sscanf(pos, "%2hhX",&byteArray[i]);
        pos = pos + 2;
    }
}


static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    SHA1_INFO ctx;

    uint8_t firstHash[SHA1_DIGEST_LENGTH];
    uint8_t secondHash[SHA1_DIGEST_LENGTH];
    
    int i;
    
    char counterString [8] = "\x00\x00\x00\x00\x00\x00\x00\x01";

    uint8_t key[SHA1_BLOCKSIZE];
    uint8_t key1[SHA1_BLOCKSIZE];
    uint8_t key2[SHA1_BLOCKSIZE];
    memset(key, 0, SHA1_BLOCKSIZE);
    toBinary(secret_hex, key);
    
    for (i = 0; i < SHA1_BLOCKSIZE; i++)
    {
        key1[i] = key[i] ^ 0x36;
    }
    for (i = 0; i < SHA1_BLOCKSIZE; i++)
    {
        key2[i] = key[i] ^ 0x5c;
    }
    
    sha1_init(&ctx);
    sha1_update(&ctx, key1, SHA1_BLOCKSIZE);
    sha1_update(&ctx, counterString, 8);

    sha1_final(&ctx, firstHash);
        
    sha1_init(&ctx);

    sha1_update(&ctx, key2, SHA1_BLOCKSIZE);
    sha1_update(&ctx, firstHash, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, secondHash);
    
    
    int offset = secondHash[19] & 0xf ;
    int bin_code = (secondHash[offset] & 0x7f) << 24
    | (secondHash[offset+1] & 0xff) << 16
    | (secondHash[offset+2] & 0xff) << 8
    | (secondHash[offset+3] & 0xff) ;

    unsigned int HOTP = bin_code % 1000000;
    char HOTPstr [7];

    sprintf(HOTPstr, "%u", HOTP);

    if (strcmp(HOTPstr, HOTP_string) == 0)
        return 1;
    else

        return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    SHA1_INFO ctx;

    uint8_t firstHash[SHA1_DIGEST_LENGTH];
    uint8_t secondHash[SHA1_DIGEST_LENGTH];
    
    int i;
        
    uint8_t timerString [8];
    unsigned long timeperiod = 30;
    unsigned long currTime = ((unsigned long)time(NULL))/timeperiod;
           
    for (i = 0; i < 8; i++)
    {
        timerString[7-i] = currTime & 0xff;
        currTime >>= 8;
    }

    
    uint8_t key[SHA1_BLOCKSIZE];
    uint8_t key1[SHA1_BLOCKSIZE];
    uint8_t key2[SHA1_BLOCKSIZE];
    memset(key, 0, SHA1_BLOCKSIZE);
    toBinary(secret_hex, key);
    
    for (i = 0; i < SHA1_BLOCKSIZE; i++)
    {
        key1[i] = key[i] ^ 0x36;
    }
    for (i = 0; i < SHA1_BLOCKSIZE; i++)
    {
        key2[i] = key[i] ^ 0x5c;
    }
    
    sha1_init(&ctx);
    sha1_update(&ctx, key1, SHA1_BLOCKSIZE);
    sha1_update(&ctx, timerString, 8);

    sha1_final(&ctx, firstHash);
        
    sha1_init(&ctx);

    sha1_update(&ctx, key2, SHA1_BLOCKSIZE);
    sha1_update(&ctx, firstHash, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, secondHash);
    
    
    int offset = secondHash[19] & 0xf ;
    int bin_code = (secondHash[offset] & 0x7f) << 24
    | (secondHash[offset+1] & 0xff) << 16
    | (secondHash[offset+2] & 0xff) << 8
    | (secondHash[offset+3] & 0xff) ;

    unsigned int TOTP = bin_code % 1000000;
    char TOTPstr [7];

    sprintf(TOTPstr, "%u", TOTP);
    if (strcmp(TOTPstr, TOTP_string) == 0)
        return 1;
    else

        return (0);
    
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
