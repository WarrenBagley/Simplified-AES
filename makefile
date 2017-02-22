all:
	g++ -c -std=c++0x -Wall -c -o aes.o aes.h
	g++ -c -std=c++0x -Wall -c -o encryptionSystem.o encryptionSystem.cpp
	g++ -o  encryptionSystem encryptionSystem.o
