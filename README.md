# About this project

This project contains two programs: 
TextEncryption: Allows users to input a message, encrypt it, and save it in a MySQL database.
Decryption: Enables users to select all encrypted messages from the database, decrypt them, and display the original content.

Encryption is performed using the RSA algorithm through the Crypto++ library accessed via a DLL. The Cryptopp_UnitTest folder contains unit tests for the C++ library, implemented with Google Test.