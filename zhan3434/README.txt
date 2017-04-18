#Xiaotian Zhang, 1002963714, xtian.zhang@mail.utoronto.ca
#Haoyue Peng, 1003146918, haoyue.peng@mail.utoronto.ca

generateQRcode:
We first reformatted the variables: issuer, accountName, secret_hex. ASCII characters are transformed into hex. And those hex numbers are then converted into base32 numbers with base32_encode(). Finally the URL and QR code is generated. 

validateQRcode:
We followed the formula and instructions. Ipad and opad keys are generated and messages are hashed in HOTP and TOTP the the corresponding messages. The validation is tested in these two functions.
