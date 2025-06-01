
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <stdexcept>

#include "AES.h"      
#include "SE.h"          
#include "FHE/FHE_utils.hpp" 

// Simple assertion function
void assert_hybrid_true(bool condition, const std::string& test_name) {
    if (!condition) {
        std::cerr << "[HYBRID TEST FAILED] " << test_name << std::endl;
        throw std::runtime_error("Assertion failed in hybrid test: " + test_name);
    }
    std::cout << "[HYBRID TEST PASSED] " << test_name << std::endl;
}

int main() {
    try {
        std::cout << "--- Running Hybrid SSE-FHE Test ---" << std::endl;

        std::vector<uint8_t> sse_aes_key = {0x00, 0xAA, 0xBB, 0xCC}; 
        SE se_service(sse_aes_key);

        FHEUtils fhe_manager; 

        std::map<std::string, seal::Ciphertext> user_encrypted_scores;
        std::map<std::string, int64_t> user_plain_scores;

        user_plain_scores["user1"] = 100;
        user_encrypted_scores["user1"] = fhe_manager.encrypt(user_plain_scores["user1"]);
        se_service.add("genre:sci-fi", {"user1"});
        se_service.add("platform:pc", {"user1"});

        user_plain_scores["user2"] = 150;
        user_encrypted_scores["user2"] = fhe_manager.encrypt(user_plain_scores["user2"]);
        se_service.add("genre:fantasy", {"user2"});
        se_service.add("platform:console", {"user2"});
        
        user_plain_scores["user3"] = 120;
        user_encrypted_scores["user3"] = fhe_manager.encrypt(user_plain_scores["user3"]);
        se_service.add("genre:sci-fi", {"user3"});
        se_service.add("platform:console", {"user3"});

        std::cout << "[+] Data populated into SSE and FHE-encrypted scores stored." << std::endl;
        std::string query_keyword = "genre:sci-fi";
        std::cout << "[+] Searching SSE for keyword: " << query_keyword << std::endl;
        
        std::vector<std::string> hex_encrypted_user_ids = se_service.search(query_keyword);
        
        std::vector<std::string> plain_user_ids;
        std::cout << "[+] Found " << hex_encrypted_user_ids.size() << " encrypted user ID(s). Decrypting them..." << std::endl;
        for (const auto& hex_id : hex_encrypted_user_ids) {
            plain_user_ids.push_back(se_service.decryptDocIDFromHex(hex_id));
        }
        
        std::sort(plain_user_ids.begin(), plain_user_ids.end());
        std::vector<std::string> expected_user_ids = {"user1", "user3"};
        std::sort(expected_user_ids.begin(), expected_user_ids.end());
        assert_hybrid_true(plain_user_ids == expected_user_ids, "SSE search and decryption of user IDs");
        for(const auto& id : plain_user_ids) std::cout << "  - Decrypted User ID: " << id << std::endl;

        if (plain_user_ids.empty()) {
            std::cout << "[+] No users found for the query. Sum is 0." << std::endl;
            assert_hybrid_true(true, "Sum of scores for empty user set (vacuously true)");
        } else {
            seal::Ciphertext total_score_ct = fhe_manager.encrypt(0); 
            int64_t expected_plain_sum = 0;

            std::cout << "[+] Summing FHE-encrypted scores for found users..." << std::endl;
            for (const auto& user_id : plain_user_ids) {
                if (user_encrypted_scores.count(user_id)) {
                    total_score_ct = fhe_manager.add(total_score_ct, user_encrypted_scores.at(user_id));
                    expected_plain_sum += user_plain_scores.at(user_id);
                } else {
                     std::cerr << "Warning: User ID " << user_id << " found by SSE but has no FHE score." << std::endl;
                }
            }

            // Decryption and Verification
            int64_t decrypted_total_score = fhe_manager.decrypt(total_score_ct);
            std::cout << "[+] Decrypted total score: " << decrypted_total_score << std::endl;
            std::cout << "[+] Expected plain total score: " << expected_plain_sum << std::endl;
            assert_hybrid_true(decrypted_total_score == expected_plain_sum, "Homomorphic sum of FHE-encrypted scores");
        }

        std::cout << "\n[✔] Hybrid SSE-FHE test completed successfully!" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "An exception occurred during Hybrid tests: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}