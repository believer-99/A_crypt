#include "FHE/FHE.h"
#include <iostream>

using namespace hybridcrypto::fhe;

int main() {
    FHE fhe;
    int original = 5;
    fhe.encryptInteger(original);
    std::cout << "Encrypted: " << original << std::endl;

    int to_add = 3;
    fhe.addEncrypted(to_add);
    std::cout << "Added: " << to_add << std::endl;

    int to_multiply = 2;
    fhe.multiplyEncrypted(to_multiply);
    std::cout << "Multiplied by: " << to_multiply << std::endl;

    fhe.decryptInteger();
    int result = fhe.getDecryptedValue();
    std::cout << "Decrypted result: " << result << std::endl;

    int expected = (original + to_add) * to_multiply;
    if (result == expected) {
        std::cout << "Test Passed: " << result << " == " << expected << std::endl;
    } else {
        std::cout << "Test Failed: Got " << result << ", expected " << expected << std::endl;
    }

    return 0;
}
