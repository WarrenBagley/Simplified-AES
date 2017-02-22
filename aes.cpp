/****************************************************************
*
*	Name: Warren Bagley
*	Assignemnt: Project 2 - Simplified AES
*	Date: December 7, 2016
*	File: aes.cpp
*	Description: The implementation file for the class AES
*
*****************************************************************/

#include <iostream>
#include <string>
#include <vector>
#include "aes.h"

AES::AES(std::string encrypted, std::string cipherkey)
//Constructor for AES
{
	message = encrypted;
	key = cipherkey;
}

void AES::pad()
//Pads the cipher message with 'A's to get uniform 4x4 blocks
{
	for(int i = (cipherMessage.length()%16); i<16; i++)
	{
		cipherMessage.push_back('A');
	}
}


void AES::shiftRows()
//Shifts the rows of the 4x4 blocks
{
	std::string shiftHold = "", copyConst = "";
	int shiftCount = 0; //Determines shifting behavior of each row
	for(unsigned int i=0; i<cipherMessage.length(); i += 4)
	{
		shiftHold.append(cipherMessage, i, 4);

		if(shiftCount%4 != 0)	//Checks for first row in block
		{
			copyConst.append(shiftHold, 0, shiftCount);
			cipherMessage.erase(i, shiftCount);
			cipherMessage.insert(i + (4-shiftCount), copyConst);
		}

		shiftHold = "";	
		copyConst = "";
		shiftCount++;

		if(shiftCount >= 4)	//New block
		{
			shiftCount = 0;
		}
	}
}

AES::Vigenere::Vigenere(std::string msg, std::string cipherKey)
//Constructor
{
	message = msg;
	key = cipherKey;
}

void AES::vigenereCipher(std::string unencrypted, std::string key)
//Performs the Vigenere Cipher on a plaintext message
{
	Vigenere cipher(unencrypted, key);
	cipher.encrypt();
	cipherMessage = cipher.getEncrypted();
}

void AES::Vigenere::encrypt()
//Performs encryption using a Vigenere Cipher
{
	int keyTrack = 0;
	for(unsigned int i=0; i < message.length(); i++)	//Encrypt each character
	{	
		char target = message[i];
		encrypted += (((target-'A') + (key[keyTrack] - 'A')) % 26) + 'A';
		keyTrack = (keyTrack+1) % key.length();	
	}
}

AES::ParityBit::ParityBit()
{
	//Default constructor
}

AES::ParityBit::ParityBit(std::string input)
{
	setParityInput(input);
}

int AES::ParityBit::bitCount(int count)
//Counts the number of bits
//Source: 
//	Article: Bit Fiddling - 3
//      Author: Jeu Geogre
//	Organization: Microsoft
//	Date: June 8, 2005
//	Date of Access: December 5, 2016
//      Link: https://blogs.msdn.microsoft.com/jeuge/2005/06/08/bit-fiddling-3/
{
	int bits;

	bits = count -((count >> 1) & 033333333333)-((count>>2) & 011111111111);
	return ((bits + (bits >> 3)) & 030707070707) % 63;
}

void AES::ParityBit::setParityInput(std::string input)
//Sets the parity bits for each block
{
	unsigned int bits;
	unsigned char ascii;
	for(unsigned int i=0; i<input.length(); i++)	//Iterate through each block
	{
		ascii = input[i];
		bits = bitCount(ascii);	//Count the number of bits
		if(bits%2 != 0)	//Odd number of bits
		{
			ascii += 128;
		}
		parityLine.push_back(ascii);
	}	
}

void AES::MixColumns::generateRijndael()
//Generates the matrix for Rijndael's Galois Fields
{
	int data = 1;
	rijndael[0][2] = data;
	rijndael[0][3] = data;
	rijndael[1][0] = data;
	rijndael[1][3] = data;
	rijndael[2][0] = data;
	rijndael[2][1] = data;
	rijndael[3][1] = data;
	rijndael[3][2] = data;
	data++;
	for(int i=0; i<4; i++)
	{
		rijndael[i][i] = data;
	}
	data++;
	for(int j=0; j<4; j++)
	{
		rijndael[j][j+1] = data;
	}
	rijndael[3][0] = data;
}

unsigned int AES::MixColumns::rgfMul(unsigned int hexa, int multiple)
//Special operations for Rijndael's Galois Fields multiplication
{
	unsigned int product;
	if(multiple == 1)	// *1
	{
		return hexa;
	}
	else if(multiple == 2)	// *2
	{
		product = hexa << 1;	//Shift left
		if(product >= 256)	//Cut off bits>8
		{
			product = product-256;

		}
		if(hexa >= 128)	//If the MSB is 1, XOR with 0001 1011
		{
			product = product ^ 27;
		}
		return product;
	}
	else if(multiple == 3)	// *3
	{
		product = (hexa << 1)^hexa;	//Shift left
		if(product >= 256)
		{
			product = product-256;	//Cut off bits>8
		}
		if(hexa >= 128)	//If the MSB is 1, XOR with 0001 1011
		{
			product = product ^ 27;
		}
		return product;
	}
	else	//Other numbers, default to *1
	{
		std::cout << "Error: invalid rgfMul operation\n";
		return hexa;
	}
}

std::vector<unsigned int> AES::RGField(std::vector<unsigned int> parityBits)
//Mixes columns using Rijndael's Galois fields
{
	std::vector<unsigned int> mixed;
	unsigned int insertValue;
	unsigned int block[4][4]; //Gets the block
	unsigned int column[4];	//Used to examine each column
	for(unsigned int i=0; i < parityBits.size(); i+=16)	//Iterate through the entire message
	{
		for(unsigned int j=i, l=0;j<i+16; j+=4)	//Get the block
		{
			for(int k=0; k<4; k++)
			{
				block[l][k] = parityBits.at(j+k);
			}
			l++;
		}

		for(int a=0; a<4; a++)	//Multiply each row by the column
		{
			for(int b=0, x=0; b<4; b++) //Multiply each value
			{
				insertValue = 0;
				while(x<4)
				{
					column[x] = mixedCol.rgfMul(block[x][a], mixedCol.rijndael[b][x]);
					insertValue = insertValue ^ column[x];
					x++;
				}
				mixed.push_back(insertValue);
				x = 0;
			}
		}
	}

	return mixed;
}

