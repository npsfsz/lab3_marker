#Ali Aamir, 999940710, aliyahya.aamir@mail.utoronto.ca
#Abhijit Kambalapally, 999864703, abhijit.kambalapally@mail.utoronto.ca

Part 1: Generating an otpauth:// URI (generateQRcode.c)

1. Encoded the issuer and accountname inputs with urlEncode. 
2. Converted secret hex string into an array of bytes (uint8_t) size 10
3. Use the base32_encode() on this byte array
4. Create hotp and totp strings with encoded params
5. Display the two QRcodes


Part 2: Validating the Codes (validateQRcode.c)

Validate HOTP:

1. Create an 8-byte counter (message) with value 1
2. Convert 20 character secret hex into byte array
3. Append zeros to the end of the key in k_ipad to match the 
   sha1_blocksize and compute the inner pad by XORing the key with 0x36
4. Append zeros to the end of the key in k_opad to match the 
   sha1_blocksize and compute the outer pad by XORing the key with 0x5c
5. Compute the inner hash by concatenating k_ipad with the counter (message)
6. Compute the final HMAC by concatentating the hash of step 5 with k_opad
7. Take the first 6 characters of the HMAC
8. Compare with provided HOTP value
9. Output valid or invalid


Validate TOTP:

1. Get the current time and divide it by a time step of 30
1. Create an 8-byte time_steps array (message) with the value of step 1
3. Convert 20 character secret hex into byte array
4. Append zeros to the end of the key in k_ipad to match the 
   sha1_blocksize and compute the inner pad by XORing the key with 0x36
5. Append zeros to the end of the key in k_opad to match the 
   sha1_blocksize and compute the outer pad by XORing the key with 0x5c
6. Compute the inner hash by concatenating k_ipad with the time_steps (message)
7. Compute the final HMAC by concatentating the hash of step 5 with k_opad
8. Take the first 6 characters of the HMAC
9. Compare with provided HOTP value
10. Output valid or invalid


