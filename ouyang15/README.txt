#Yike Ouyang, 1002704406, yike.ouyang@mail.utoronto.ca

#Siyuan Chen, 1002751337, siyuansiyuan.chen@mail.utoronto.ca

generateQRcode.c:
We encode the accountname, the issuer and the secret into suitable format by using the function urlEncode() and base32_encode().Note that, for the secret, we first convert the ASCII character into the hex format and then use the function base32_encode() to encode hex into the base-32 value. Finally, the encoded value will be put into the URL.

validateQRCode.c:
Basically, we refer to the formula HMAC = H[(K ⊕ opad) || H((K ⊕ ipad) || M)]. According to this formula, we using the secret to generate both the ipad and opad and use the HMAC function to hash the value twice. We use the value to verify whether the user has provided correct value. The values in the HTOP and TOTP are different. The former one is the counter value 1 and the latter is the current time.
