# Pranav Mehndiratta, 999480725, pranav.mehndiratta@mail.utoronto.ca
# Vaibhav Vijay, 1000073029, vaibhav.vijay@mail.utoronto.ca


Part 1:
	generateQRCode.c
	create the URI used in generating the QR code when provided with an account name, issuer and a secret key

	Implementation

	-> Convered into a byte array and then base32 encoded 
	-> URI is generated and displayed

Part 2:
	validateQRCode.c
	checks if a given HOTP and TOTP strings are accurate based on the given secret key

	Implementation
	-> construct the innser sha block by taking (secret_key^0x36)
	-> For HOTP, set counter = 1 and TOTP, set counter to unix_time/30 (period of 30 seconds)
	-> Try matching the result, if its matched return 1 else 0.