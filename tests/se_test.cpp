#include <iostream>
#include "../include/SE.h"

int main() {
    std::vector<uint8_t> key = {0x00, 0x01, 0x02, 0x03};
    SE se(key);

    se.add("hello", {"doc1", "doc2"});
    se.add("world", {"doc3"});

    std::vector<std::string> result1 = se.search("hello");
    std::vector<std::string> result2 = se.search("world");
    std::vector<std::string> result3 = se.search("notfound");

    std::cout << "Results for 'hello':\n";
    for (const auto& doc : result1) std::cout << doc << " ";
    std::cout << "\nResults for 'world':\n";
    for (const auto& doc : result2) std::cout << doc << " ";
    std::cout << "\nResults for 'notfound':\n";
    for (const auto& doc : result3) std::cout << doc << " ";
    std::cout << std::endl;

    return 0;
}
