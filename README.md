# 🔐 Acrypt - Hybrid Cryptographic Encryption Library

Acrypt is a **modular C++ cryptographic library** that combines the strengths of:

- 🔒 **AES (Advanced Encryption Standard)** – for fast and secure symmetric encryption.
- 🔍 **Searchable Symmetric Encryption (SSE)** – enabling keyword search over encrypted data.
- 🧠 **Fully Homomorphic Encryption (FHE)** – for computation on encrypted data without decryption.

This hybrid model allows building **privacy-preserving** and **searchable secure systems** by combining modern cryptographic primitives, offering a balance of performance, security, and usability.

---

## ✨ Features

- ✅ Modular design with clearly separated encryption modules.
- ✅ CMake-based cross-platform build system.
- 🔐 AES encryption and decryption with CBC mode.
- 🔎 SSE-style keyword and document ID encryption (Work In Progress).
- 🧠 FHE setup and basic encryption/decryption using Microsoft SEAL (Planned).
- 🧪 Unit-test driven development (for each module separately).
- 🧰 Designed for backend integration, research, and custom secure communication tools.

---

## 📁 Project Structure

```bash
Acrypt/
├── include/              # Header files (API layer for each module)
│   ├── AES/              # AES interface
│   └── SE/               # Searchable Encryption interface
├── src/                  # Source code for each module
│   ├── AES/              # AES implementation
│   └── SE/               # Searchable Encryption implementation
├── tests/                # Test files for individual modules
├── CMakeLists.txt        # Project-wide build configuration
└── README.md             # You're reading this 😄
