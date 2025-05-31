#include <iostream>
#include "../include/FHE/FHE_utils.hpp"

int main() {
    std::cout << "[+] Initializing FHE Utilities...\n";
    FHEUtils fhe;

    int64_t num1 = 25;
    int64_t num2 = 17;

    std::cout << "[+] Encrypting numbers: " << num1 << " and " << num2 << std::endl;

    seal::Ciphertext enc1 = fhe.encrypt(num1);
    seal::Ciphertext enc2 = fhe.encrypt(num2);

    std::cout << "[+] Performing homomorphic addition...\n";
    seal::Ciphertext encrypted_result = fhe.add(enc1, enc2);

    std::cout << "[+] Decrypting the result...\n";
    int64_t decrypted_result = fhe.decrypt(encrypted_result);

    std::cout << "[+] Decrypted Result: " << decrypted_result << std::endl;

    if (decrypted_result == (num1 + num2)) {
        std::cout << "[✔] Test Passed! Encrypted addition worked as expected.\n";
    } else {
        std::cout << "[✘] Test Failed! Expected " << (num1 + num2) << " but got " << decrypted_result << "\n";
    }

    return 0;
}
