#ifndef HYBRIDCRYPTO_FHE_H
#define HYBRIDCRYPTO_FHE_H

#include "seal/seal.h"
#include "seal/batchencoder.h"
#include <memory>

namespace hybridcrypto::fhe {

class FHE {
public:
    FHE();

    void encryptInteger(int value);
    void decryptInteger();
    void addEncrypted(int value);
    void multiplyEncrypted(int value);
    int getDecryptedValue() const;

private:
    void initialize();

    seal::EncryptionParameters parms_;
    std::shared_ptr<seal::SEALContext> context_;

    seal::PublicKey public_key_;
    seal::SecretKey secret_key_;

    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    std::unique_ptr<seal::BatchEncoder> encoder_;

    seal::Ciphertext encrypted_;
    int last_plaintext_result_;
};

}

#endif
