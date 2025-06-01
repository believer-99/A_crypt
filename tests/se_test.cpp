#include <iostream>
#include <vector>
#include <string>
#include <algorithm> // For std::sort
#include <stdexcept> // For std::runtime_error
#include "SE.h"      // Corrected include path

bool compare_string_vectors_sorted(std::vector<std::string> v1, std::vector<std::string> v2) {
    std::sort(v1.begin(), v1.end());
    std::sort(v2.begin(), v2.end());
    return v1 == v2;
}

void assert_true(bool condition, const std::string& test_name) {
    if (!condition) {
        std::cerr << "[TEST FAILED] " << test_name << std::endl;
        throw std::runtime_error("Assertion failed in test: " + test_name);
    }
    std::cout << "[TEST PASSED] " << test_name << std::endl;
}

int main() {
    try {

        std::vector<uint8_t> key = {0x00, 0x01, 0x02, 0x03};
        SE se(key);

        std::cout << "--- Running SE Tests ---" << std::endl;

        se.add("keyword1", {"doc1", "doc2"});
        std::vector<std::string> result_k1 = se.search("keyword1");
        std::vector<std::string> expected_k1_encrypted = {"646f6331", "646f6332"};
        assert_true(compare_string_vectors_sorted(result_k1, expected_k1_encrypted), "Search for keyword1");

        std::vector<std::string> decrypted_k1_result;
        for(const auto& enc_id : result_k1) {
            decrypted_k1_result.push_back(se.decryptDocIDFromHex(enc_id));
        }
        std::vector<std::string> expected_k1_decrypted = {"doc1", "doc2"};
        assert_true(compare_string_vectors_sorted(decrypted_k1_result, expected_k1_decrypted), "Decrypt DocIDs for keyword1");

        se.add("keyword2", {"doc3"});
        std::vector<std::string> result_k2 = se.search("keyword2");
        std::vector<std::string> expected_k2_encrypted = {"646f6333"};
        assert_true(compare_string_vectors_sorted(result_k2, expected_k2_encrypted), "Search for keyword2");

        std::vector<std::string> result_nonexistent = se.search("nonexistent_keyword");
        assert_true(result_nonexistent.empty(), "Search for non-existent keyword");

        se.add("keyword1", {"doc4"}); 
        result_k1 = se.search("keyword1");
        expected_k1_encrypted = {"646f6331", "646f6332", "646f6334"}; 
        assert_true(compare_string_vectors_sorted(result_k1, expected_k1_encrypted), "Search for keyword1 after adding more docIDs");

        se.add("empty_keyword", {});
        std::vector<std::string> result_empty = se.search("empty_keyword");
        assert_true(result_empty.empty(), "Search for keyword added with empty docID list");

        se.add("Keyword1", {"doc_upper"});
        std::vector<std::string> result_Keyword1 = se.search("Keyword1");
        std::vector<std::string> expected_Keyword1_encrypted = {"646f635f7570706572"};
        assert_true(compare_string_vectors_sorted(result_Keyword1, expected_Keyword1_encrypted), "Search for 'Keyword1' (case sensitive)");
        result_k1 = se.search("keyword1");
        assert_true(compare_string_vectors_sorted(result_k1, expected_k1_encrypted), "Re-Search for 'keyword1' (unaffected by 'Keyword1')");


        std::cout << "[✔] All SE tests passed successfully!" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "An exception occurred during SE tests: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}