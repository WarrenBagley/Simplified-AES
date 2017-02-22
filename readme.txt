+-----------------------------------------------+
|						|
|	Project: Project 2 - Simplified AES	|
|	Author: Warren Bagley			|
|	Due Date: December 7, 2016		|
|	Files:					|
|		encryptionSystem.cpp		|
|		aes.h				|
|		aes.cpp				|
|		makefile			|
|						|
+-----------------------------------------------+

Description: This program takes in a specified text file containing
	     a plaintext message, and a text file containing a
	     plaintext key. It then performs a simplified version
	     of the AES encryption algorithm. It also outputs the
	     steps taken by the algorithm to a specified text file.

Use: To use the program, use the 'make' command in the program's directory
     and use the command './encryptionSystem'

Sources:

	1.	Function: int AES::ParityBit::bitCount(int count);
		Location:
			File: aes.cpp
			Lines: 97-111
		Source: "Bit Fiddling - 3"
		Author: Jeu George
		Publisher: Microsoft
		Publish Date: June 8, 2005
		Date of Access: December 6, 2016
		Link: https://blogs.msdn.microsoft.com/jeuge/2005/06/08/bit-fiddling-3/

	