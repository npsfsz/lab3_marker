#Thanushan Karunaharan, 999598573, thanushan.karunaharan@mail.utoronto.ca
#Ajuthan Vijayasri, 999682151, ajuthan.vijayasri@mail.utoronto.ca

Part 1:
-------
For Part 1, we were to work on generating a special URI and QR code for TOTP and HOTP. Given that we were allowed to assume a valid 20-character hex key value, we just needed to encode the key to a 80 bit base32 value. This was done by first convertinging the "secret_hex" char array into a byte array. Next the array was encoded with base32 encoding. During this time, the accountName and issuer strings are both encoded with the provided urlEncode function. With the values we have, the URI strings were constructed and also used to generate the QR codes (by calling the provided displayQRcode function).

Part 2: 
-------
For Part 2, we're to validate a given QR code given the secret key. Both HOTP and VOTP needed to be validated.

For validating HOTP, we first converted the "secret_hex" char array into a 10 element byte array. Next we padding the byte array with zeros to the right (upto blocksize 64 bytes), and had every byte XOR'd with 0x5c and 0x36 to genereate the ipad and opad. The two newly created keypads were then hashed using the SHA-1 hash function. Firstly the inner digest was computed using the ipad and counter 1 converted to a 8-byte array (H((K ⊕ ipad) || 1)). Next the outer digest was computed using the opad and inner digest value (H((K ⊕ opad) || innerDigest)). After the double hash with the SHA-1 function, the returned value is converted into a 4-byte value (using Dynamic Truncation code provided in document) then to a 6-bit HOTP value. This value is compared with the provded user string to determine if they match or not.

For validating TOTP, it's almost exactly the same as HOTP, however the data value passed in along with the key (hotp passed in 1, which is it's counter), is the timestep value. The timestep value is calculated by retrieving the current unix time in seconds and dividing it by the period, which is set to 30 seconds in this lab. This value (after converting it to a 8-byte array) is passed along with the secret_hex value to the HOTP generating functions mentioned above, which end up returning the TOTP value. The value is compared with the provided user string to determine if they match or not. 