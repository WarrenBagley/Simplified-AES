/**********************************************************
*
*	Name: Warren Bagley
*	Assignemnt: Project 2 - Simplified AES
*	Date: December 7, 2016
*	File: encryptionSystem.h
*	Description: The driver file that performs a
*	simplified version of AES on a message.
*
**********************************************************/


#include <iostream>
#include <algorithm>
#include <cctype>
#include <locale>
#include <fstream>
#include <string>
#include <vector>
#include "aes.h"
#include "aes.cpp"

std::string preProcess(std::string pre_string);
//Converts all characters to uppercase and removes whitespace and punctuation
void AdvancedEncryptionSystem(std::string outputName, std::string message, std::string key);
//Performs the modified AES algorithm and outputs the steps to a .txt file

int main(int argc, char** argv)
{
	//Get the file names:
	std::ifstream inMessage, keyFile;
	std::string input_key, output_ciphertext, input_plaintext, outputFileName;
	std::cout << "Enter the name of the input plaintext file: ";
	std::cin >> input_plaintext;
	inMessage.open(input_plaintext.c_str());
	
	std::cout << "Enter the name of they key file: ";
	std::cin >> input_key;
	keyFile.open(input_key.c_str());

	std::cout << "Enter the name of the output file: ";
	std::cin >> outputFileName;

	if(!inMessage.is_open() || !keyFile.is_open())	//Check if file is open
	{
		//Check if file is opened correctly
		std::cout << "Error: Input file failed to open.\n";
	}
	
	else
	{
		//Get the output file:
		std::string orig, key;
		getline(inMessage, orig, '\n'); 
		getline(keyFile, key, '\n');

		AdvancedEncryptionSystem(outputFileName, orig, key);	//Perform encryption
	}	
	return 0;
}

std::string preProcess(std::string pre_string)
//Takes a string, removes whitespace and punctuation, and returns the processed string.
{
	std::locale loc;
	std::string post_string;
	for(unsigned int i=0; i<pre_string.length(); i++)
	{
		pre_string[i] = std::toupper(pre_string[i], loc);
		if(ispunct(pre_string[i]))
		{
			pre_string.erase(i);
		}
	}
	pre_string.erase(remove_if(pre_string.begin(), pre_string.end(), isspace), pre_string.end());
 
	return pre_string;
}

void AdvancedEncryptionSystem(std::string outputName, std::string message, std::string key)
{
	//Set up variables and prepare output file:
	std::string processed, encrypted, padded, shifted;
	std::ofstream stepOutput;
	stepOutput.open(outputName.c_str());
	if(!stepOutput.is_open())
	{
		std::cout << "Error: Output file failed to open\n";
	}
	else
	{
		//Preprocessing:
		stepOutput << "Preprocessing\n";
		processed = preProcess(message);
		stepOutput << processed << std::endl << std::endl;

		AES encrypt(processed, key);

		//Substitution:
		stepOutput << "Substitution:\n";
		encrypt.vigenereCipher(encrypt.returnMessage(), encrypt.returnKey());
		stepOutput << encrypt.returnCiphMessage() << std::endl << std::endl;

		//Padding:
		stepOutput << "Padding:\n";
		encrypt.pad();
		for(unsigned int i=0; i<encrypt.returnCiphMessage().length(); i += 4)
		{
			stepOutput << encrypt.returnCiphMessage().substr(i, 4) << std::endl;
		}
		stepOutput << std::endl;

		//Shift Rows:
		stepOutput << "ShiftRows:\n";
		encrypt.shiftRows();
		for(unsigned int j=0; j<encrypt.returnCiphMessage().length(); j +=4)
		{
			stepOutput << encrypt.returnCiphMessage().substr(j, 4) << std::endl;
		}
		stepOutput << std::endl;

		//Parity Bit:
		stepOutput << "Parity Bit:\n";
		encrypt.setParityBits();
		std::vector<unsigned int> printParity = encrypt.returnParity();

		for(unsigned int k=0; k<printParity.size(); k++)
		{
			stepOutput << std::hex << printParity.at(k);
			if(k%4 == 3)
			{
				stepOutput << std::endl;
			}
			else
			{
				stepOutput << " ";
			}
		}
	
		//Mix Columns:
		stepOutput << std::endl << "MixColumns:\n";		
		std::vector<unsigned int> result = encrypt.RGField(encrypt.returnParity());
		for(unsigned int m=0; m<result.size(); m += 16)
		{
			for(unsigned int n=0; n<4; n += 1)
			{
				for(unsigned int o=m+n; o<16+m; o +=4)
				{
					stepOutput << result.at(o) << " ";
				}
				stepOutput << std::endl;
			}
		}
	}
}
