#Jacob Geisberger, 1001588212, jacob.geisberger@mail.utoronto.ca
#Desmond Sisson, 1001669492, desmond.sisson@mail.utoronto.ca

Part 1:
After reading the encoding libraries and the RFC files, we read in info and converted it from hex
to binary in the uint8_t format. This allowed us to call the base32_encode function properly. We
then used a lot of string concatenation to create the HOTP and TOTP URI strings, and called the
provided QR encode library to display the QR codes. Scanning the codes on our phones produced the
correct strings.

Part 2:
After parsing the secret, we turn the hex back into binary. To calculate HMAC-SHA-1(K,C), we pad
the binary with zeroes, and XOR the keys with the opad and ipad from class. Using the provided
sha1 function, we calculate HMAC = H( key1 || H( key2 || message ) ), and then calculate DT(HMAC).
We then mod the number to our given length (6 digits) and compare the values. The process for
validateTOTP is identical, except the message is the time rather than the counter. Comparing to
a validation app on our phone, the numbers match up, and the TOTP value does indeed change every
30 seconds.
