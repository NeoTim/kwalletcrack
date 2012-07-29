dummy:
	 g++ -Wall -O3 kwalletcrack.c blowfish.cc cbc.cc blockcipher.cc -lcrypto -o kwalletcrack
