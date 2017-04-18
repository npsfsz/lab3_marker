#Justin Canton, 1000017910, justin.canton@mail.utoronto.ca
#Risitha Tennakoon Mudiyanselage, 999887181, risitha.tennakoonmudiyanselage@mail.utoronto.ca

In this lab we implemented 2 applications. One generates a QR code from the input of an account name, an issuer, and a secret hex. The other decrypts the values and determines if they match by entering the secret hex, HTOP and TOTP.

In generateQRcode, we padded the secret hex to make sure it was 20 chars, then convert the char array to uint. We then sent it into the supplied function base32_encode to encode the value. We then urlEncode the issuer and accountName, then we print out the values on the screen through the function displayQRcode.

In validateQRcode, we had 2 different paths. To validate HOTP, we again pad the secret hex input, then e convert to a uint. We then use this value as both the inner and outer pad, XORing them with 0x36 and 0x5C respectively. We then run sha1 on the inner pad and the data input to get the inner sha. Following this, we run sha1 again on the outer pad and the results of the inner sha to get the outer sha. We the use the function that turns the 20 bit sha1 value into 31 bit string, and we have our HOTP. TOTP is much the same, but the data passed in is the current timestamp, since the TOTP value changes every 30 seconds.
