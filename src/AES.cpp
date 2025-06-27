#include "AES.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

AES::AES(const std::vector<uint8_t> &key)
{
    if (key.size() != AES_256_KEY_SIZE)
    {
        throw std::invalid_argument("AES key must be " + std::to_string(AES_256_KEY_SIZE) + " bytes for AES-256.");
    }
    key_ = key;
}

std::vector<uint8_t> AES::gcm_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &aad)
{
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    int ciphertext_len = 0;
    std::vector<uint8_t> ciphertext_buf;
    std::vector<uint8_t> tag(GCM_TAG_SIZE);

    try
    {
        if (!(ctx = EVP_CIPHER_CTX_new()))
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw std::runtime_error("Failed to initialize GCM encryption");

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr))
            throw std::runtime_error("Failed to set GCM IV length");

        if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv.data()))
            throw std::runtime_error("Failed to set GCM key and IV");

        if (!aad.empty())
        {
            if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()))
                throw std::runtime_error("Failed to process AAD");
        }

        ciphertext_buf.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        if (1 != EVP_EncryptUpdate(ctx, ciphertext_buf.data(), &len, plaintext.data(), plaintext.size()))
            throw std::runtime_error("GCM EncryptUpdate failed");
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext_buf.data() + len, &len))
            throw std::runtime_error("GCM EncryptFinal failed");
        ciphertext_len += len;
        ciphertext_buf.resize(ciphertext_len);

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()))
            throw std::runtime_error("Failed to get GCM tag");

        EVP_CIPHER_CTX_free(ctx);

        std::vector<uint8_t> result;
        result.reserve(iv.size() + ciphertext_buf.size() + tag.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext_buf.begin(), ciphertext_buf.end());
        result.insert(result.end(), tag.begin(), tag.end());

        return result;
    }
    catch (...)
    {
        if (ctx)
            EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<uint8_t> AES::gcm_decrypt(const std::vector<uint8_t> &iv_ciphertext_tag_blob, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &aad)
{
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    int plaintext_len = 0;
    int ret_val = 0;
    std::vector<uint8_t> plaintext_buf;

    if (iv_ciphertext_tag_blob.size() < GCM_TAG_SIZE)
    {
        throw std::runtime_error("Ciphertext too short to contain a tag.");
    }
    std::vector<uint8_t> ciphertext(iv_ciphertext_tag_blob.begin(), iv_ciphertext_tag_blob.end() - GCM_TAG_SIZE);
    std::vector<uint8_t> tag(iv_ciphertext_tag_blob.end() - GCM_TAG_SIZE, iv_ciphertext_tag_blob.end());

    try
    {
        if (!(ctx = EVP_CIPHER_CTX_new()))
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            throw std::runtime_error("Failed to initialize GCM decryption");

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr))
            throw std::runtime_error("Failed to set GCM IV length");

        if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), iv.data()))
            throw std::runtime_error("Failed to set GCM key and IV for decryption");

        if (!aad.empty())
        {
            if (!EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()))
                throw std::runtime_error("Failed to process AAD during decryption");
        }

        plaintext_buf.resize(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        if (!EVP_DecryptUpdate(ctx, plaintext_buf.data(), &len, ciphertext.data(), ciphertext.size()))
            throw std::runtime_error("GCM DecryptUpdate failed");
        plaintext_len = len;

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag.data()))
            throw std::runtime_error("Failed to set GCM expected tag");

        ret_val = EVP_DecryptFinal_ex(ctx, plaintext_buf.data() + len, &len);

        EVP_CIPHER_CTX_free(ctx);

        if (ret_val > 0)
        {
            plaintext_len += len;
            plaintext_buf.resize(plaintext_len);
            return plaintext_buf;
        }
        else
        {
            throw std::runtime_error("GCM decryption failed: Tag verification failed or other error.");
        }
    }
    catch (...)
    {
        if (ctx)
            EVP_CIPHER_CTX_free(ctx);
        throw;
    }
}

std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t> &plaintext)
{
    std::vector<uint8_t> iv(GCM_IV_SIZE);
    if (RAND_bytes(iv.data(), GCM_IV_SIZE) != 1)
    {
        throw std::runtime_error("Failed to generate random IV");
    }
    return gcm_encrypt(plaintext, iv);
}

std::vector<uint8_t> AES::encrypt_deterministic(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &provided_iv)
{
    if (provided_iv.size() != GCM_IV_SIZE)
    {
        throw std::invalid_argument("Provided IV must be " + std::to_string(GCM_IV_SIZE) + " bytes for GCM.");
    }
    return gcm_encrypt(plaintext, provided_iv);
}

std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t> &iv_ciphertext_tag_blob)
{
    if (iv_ciphertext_tag_blob.size() < GCM_IV_SIZE + GCM_TAG_SIZE)
    {
        throw std::runtime_error("Input data too short to contain IV, ciphertext, and tag.");
    }

    std::vector<uint8_t> iv(iv_ciphertext_tag_blob.begin(), iv_ciphertext_tag_blob.begin() + GCM_IV_SIZE);
    std::vector<uint8_t> ciphertext_with_tag(iv_ciphertext_tag_blob.begin() + GCM_IV_SIZE, iv_ciphertext_tag_blob.end());
    return gcm_decrypt(ciphertext_with_tag, iv);
}