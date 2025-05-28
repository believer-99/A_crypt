cmake_minimum_required(VERSION 3.20)
project(HybridCryptoLib)

set(CMAKE_CXX_STANDARD 17)

# Set SEAL path and find the package
set(SEAL_DIR "/usr/local/lib/cmake/SEAL")
find_package(SEAL 4.1 REQUIRED)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Gather source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# 🔹 Create the library target FIRST
add_library(hybridcrypto STATIC ${SOURCES})
target_include_directories(hybridcrypto PUBLIC ${PROJECT_SOURCE_DIR}/include)

# 🔹 Now you can link SEAL
target_link_libraries(hybridcrypto PUBLIC SEAL::seal)

# 🔹 Main test executable
add_executable(main tests/main.cpp)
target_link_libraries(main PRIVATE hybridcrypto)

# 🔹 SE test executable
add_executable(se_test tests/se_test.cpp)
target_link_libraries(se_test PRIVATE hybridcrypto)

# 🔹 FHE test executable
add_executable(fhe_test tests/fhe_test.cpp)
target_link_libraries(fhe_test PRIVATE hybridcrypto)
