/**********************************************************
*
*	Name: Warren Bagley
*	Assignemnt: Project 2 - Simplified AES
*	Date: December 7, 2016
*	File: aes.h
*	Description: The header file for the class AES
*
**********************************************************/

#ifndef AES_H
#define AES_H

#include <iostream>
#include <string>
#include <vector>


class AES
//Class for AES encryption
{
private:
	class Vigenere
	//Class for the Vigenere Cipher
	{
	private:
		std::string encrypted;
		std::string key; 
		std::string message;
		std::string cipherMessage;
	public:
		Vigenere();
		Vigenere(std::string msg, std::string cipherKey);
		//Constructors

		void encrypt();
		//Encrypts the message
		std::string getEncrypted() { return encrypted; }	
		//Returns encrypted message

		void getKey(std::string inputKey); 
		//Returns the plaintext key
	};
	class ParityBit
	//Class for generating parity bits
	{

	friend class MixColumns;
	friend class AES;
	private:
		std::vector<unsigned int> parityLine; //The parity bits
	public:
		ParityBit();
		ParityBit(std::string input);
		//Constructors

		std::vector<unsigned int> getParity() { return parityLine; }; 
		//Returns the parity bits

		int bitCount(int count);	
		//Counts the number of bits in an algorithm

		void setParityInput(std::string);
		//Sets the parity bits for each block
	};

	class MixColumns
	{
	friend class ParityBit;
	friend class AES;
	private:
		unsigned int rijndael[4][4];	//Rijndael's Galois Field
	public:
		MixColumns() { generateRijndael(); } 
		MixColumns(std::vector<unsigned int> parity);
		//Constructors

		void generateRijndael();
		//Fills the Rijndael's Galois Field matrix

		unsigned int rgfMul(unsigned int hexa, int multiple);
		//Performs multiplication operations in the Galois field
	};
	std::string message, key, cipherMessage, shifted;	//Strings for holding data
	ParityBit parity;	//Parity bits
	MixColumns mixedCol;	//Mixed Columns
	std::vector<unsigned int> encryptedMessage;	//The final encrypted message 
public:
	AES(std::string unencrypted, std::string cipherkey);
	//Constructor

	void setParityBits() { parity.setParityInput(cipherMessage); };
	//Set the parity bits

	void vigenereCipher(std::string unencrypted, std::string key);
	//Create and performs a Vigenere cipher

	void pad();
	//Pads with 'A's to make uniform 4x4 blocks

	void shiftRows();
	//Shifts the rows in the blocks

	std::vector<unsigned int> returnParity() { return parity.getParity(); }
	//Returns the parity

	std::vector<unsigned int> RGField(std::vector<unsigned int> parityBits);
	//Mixes the columns using Rijndael's Galois fields

	std::vector<unsigned int> getParity();
	//Returns the parity bits

	std::string returnMessage() { return message; } 
	//Returns the message

	std::string returnKey() { return key; } 
	//Returns the key

	std::string returnCiphMessage() { return cipherMessage; } 
	//Returns the ciphered message
};
#endif