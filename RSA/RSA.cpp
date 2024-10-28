#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h> 
#include <iostream>

using namespace CryptoPP;


// Encrypt input char array using RSA algorithm
// Function is compiled into a Dynamic-link library (DLL)
extern "C" {
    __declspec(dllexport) void EncryptRSA(const unsigned char* input, int inputLength, unsigned char* output, int outputLength, char* privateKeyOut, int privateKeyLength) {
        if (outputLength < inputLength) return;
        AutoSeededRandomPool rng;

        // Generate keys
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 2048);

        RSA::PrivateKey privateKey(params);
        RSA::PublicKey publicKey(params);

        // Encrypt input and send it to output variable
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        ArraySource(input, inputLength, true,
            new PK_EncryptorFilter(rng, encryptor,
                new ArraySink(output, outputLength)
            )
        );

        // Convert private key to Base64
        std::string encodedPrivateKey;
        StringSink* stringSink = new StringSink(encodedPrivateKey);
        Base64Encoder encoder(stringSink);
        privateKey.DEREncode(encoder);
        encoder.MessageEnd();

        // Copy Base64 private key to output buffer if it fits
        if (encodedPrivateKey.size() <= static_cast<size_t>(privateKeyLength)) {
            std::copy(encodedPrivateKey.begin(), encodedPrivateKey.end(), privateKeyOut);
            privateKeyOut[encodedPrivateKey.size()] = '\0'; // Null-terminate
        }
    }

    __declspec(dllexport) bool DecryptRSA(const unsigned char* encryptedInput, int encryptedLength, const char* base64PrivateKey, unsigned char* decryptedOutput, int decryptedOutputLength) {
        AutoSeededRandomPool rng;

        // Decode the Base64-encoded private key
        RSA::PrivateKey privateKey;
        std::string decodedPrivateKey;

        try {
            StringSource(base64PrivateKey, true,
                new Base64Decoder(
                    new StringSink(decodedPrivateKey)
                )
            );


            // Load the private key
            StringSource ss(decodedPrivateKey, true);
            privateKey.Load(ss);
        } 
        catch (Exception e){
            std::cerr << "Private key decoding failed." << std::endl;
            return false;
        }

        // Decrypt
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        std::string decryptedText;

        try {
            ArraySource(encryptedInput, encryptedLength, true,
                new PK_DecryptorFilter(rng, decryptor,
                    new StringSink(decryptedText)
                )
            );

            // Copy the decrypted text to the output buffer if it fits
            if (decryptedText.size() <= static_cast<size_t>(decryptedOutputLength)) {
                std::copy(decryptedText.begin(), decryptedText.end(), decryptedOutput);
                decryptedOutput[decryptedText.size()] = '\0'; // Null-terminate
                return true; // Success
            }
            else {
                return false; // Output buffer too small
            }
        }
        catch (const Exception& e) {
            std::cerr << "Decryption failed: " << e.what() << std::endl;
            return false; // Decryption failed
        }
    }
}