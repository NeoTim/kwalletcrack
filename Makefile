dummy:
	 g++ -Wall -O3 kwalletcrack.c blowfish.cc cbc.cc blockcipher.cc -lcrypto -o kwalletcrack

test:
	 g++ -Wall -O3 testbf.cpp blowfish.cc cbc.cc blockcipher.cc -lcrypto -o testbf
	 ./testbf
