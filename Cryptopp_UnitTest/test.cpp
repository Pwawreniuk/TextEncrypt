#include "pch.h"

using namespace std;

extern "C" {
    // Declare the EncryptRSA and DecryptRSA functions from DLL
    void EncryptRSA(const unsigned char* input, int inputLength, unsigned char* output, int outputLength, char* privateKeyOut, int privateKeyOutLength);
    bool DecryptRSA(const unsigned char* encryptedInput, int encryptedLength, const char* base64PrivateKey, unsigned char* decryptedOutput, int decryptedOutputLength);
}

class RSATest : public ::testing::Test {
protected:
    const std::string message = "Hello, RSA encryption!";
    const int keySize = 2048;
    const int outputBufferSize = 256; // For a 2048-bit RSA key, ciphertext will be 256 bytes
    const int privateKeyBufferSize = 2048;

    unsigned char encrypted[256] = { 0 };
    char privateKey[2048] = { 0 };
    unsigned char decrypted[256] = { 0 };
};

TEST_F(RSATest, EncryptAndDecrypt) {
    // Check if an example message is successfully encrypted and decrypted
    EncryptRSA(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), encrypted, outputBufferSize, privateKey, privateKeyBufferSize);
    bool success = DecryptRSA(encrypted, outputBufferSize, privateKey, decrypted, outputBufferSize);
    ASSERT_TRUE(success) << "Decryption failed.";
    ASSERT_EQ(message, std::string(reinterpret_cast<char*>(decrypted))) << "Decrypted message does not match the original message.";
}

TEST_F(RSATest, InvalidDecryption) {
    // Encrypt
    EncryptRSA(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), encrypted, outputBufferSize, privateKey, privateKeyBufferSize);

    // Modify the private key to be incorrect
    privateKey[0] = '0';

    // Try to decrypt with the modified private key
    bool success = DecryptRSA(encrypted, outputBufferSize, privateKey, decrypted, outputBufferSize);

    ASSERT_FALSE(success) << "Decryption should fail with an incorrect private key.";
}
