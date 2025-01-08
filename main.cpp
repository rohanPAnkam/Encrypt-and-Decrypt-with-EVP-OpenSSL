#include<iostream>
#include "calculator.hpp"
#include<openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

bool encryptData(const unsigned char* plaintext, int plaintextLen,const unsigned char* key, 
                const unsigned char* iv, unsigned char* cipherText, int& cipherTextLen) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        std::cout << "Cipher Context - Failed!!" << std::endl;
        return false;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cout << "Error while Initializing!!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int len;
    if (EVP_EncryptUpdate(ctx, cipherText, &len, plaintext, plaintextLen) != 1) {
        std::cout << "Failed at the time of Update!!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    cipherTextLen = len;

    if (EVP_EncryptFinal_ex(ctx, cipherText + len, &len) != 1) {
        std::cout << "Failed at the time of finalization!!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
    
}

bool decryptData(const unsigned char* cipherText, int cipherTextLen, const unsigned char* key, 
                const unsigned char* iv, unsigned char* plaintext, int& plaintextLen) {
                    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cout << "Cipher Context - Failed!!" << std::endl;
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        std::cout << "Error while Initializing!!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, cipherText, cipherTextLen) != 1) {
        std::cout << "Failed at the time of Update!!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintextLen = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        std::cout << "Failed at the time of finalization!!" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main() {

    float a,b;
    int choice;
    std::cout << "Enter Values" << std::endl;
    std::cin >> a >> b;
    std::cout << "Enter Choice" << std::endl;
    std::cin >> choice;

    float ans;

    switch(choice) {
        case 1:
            ans = add(a,b);
            break;
        case 2:
            ans = sub(a,b);
            break;
        case 3:
            ans = mul(a,b);
            break;
        case 4:
            ans = division(a,b);
            break;
        default:
            std::cout << "Wrong Choice" << std::endl;
            return 0;
    }
    unsigned char plaintext[64];
    snprintf((char*)plaintext, sizeof(plaintext), "Result: %.2f", ans);

    unsigned char key[32];
    unsigned char iv[16];

    if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        std::cout << "Error generating key or IV" << std::endl;
        return 1;
    }

    unsigned char cipherText[128];
    int cipherTextLen;

    if (encryptData(plaintext, strlen((char*)plaintext), key, iv, cipherText, cipherTextLen)) {
        std::cout << "Encryption successful!" << std::endl;

        std::cout << "cipherText: ";
        for (int i = 0; i < cipherTextLen; i++) {
            printf("%02x", cipherText[i]);
        }
        std::cout << std::endl;

        std::cout << "Key: ";
        for (int i = 0; i < sizeof(key); i++) {
            printf("%02x", key[i]);
        }
        std::cout << std::endl;

        std::cout << "IV: ";
        for (int i = 0; i < sizeof(iv); i++) {
            printf("%02x", iv[i]);
        }
        std::cout << std::endl;

        unsigned char decrypted_text[128];
        int decrypted_len;

        if (decryptData(cipherText, cipherTextLen, key, iv, decrypted_text, decrypted_len)) {
            std::cout << "Decryption successful!" << std::endl;

            decrypted_text[decrypted_len] = '\0';
            std::cout << "Decrypted text: " << decrypted_text << std::endl;
        } else {
            std::cerr << "Decryption failed" << std::endl;
            return 1;
        }

    } else {
        std::cout << "Encryption failed" << std::endl;
        return 1;
    }

    return 0;
}