# 🔐 Secure Document Transfer System using RSA and AES

This project implements a secure file exchange system using a hybrid encryption approach: **RSA for key exchange** and **AES for encrypting the document**. It also features digital signature verification to ensure data integrity and authenticity.

## 💡 Features

- 🔑 RSA 2048-bit key generation and reuse
- 🔒 AES-GCM encryption for file confidentiality
- 🖋️ Digital signatures with SHA-256 for file integrity
- 🖼️ GUI-based interface using `tkinter` (Sender & Recipient tabs)
- 📦 Easy packaging of encrypted data in JSON format
- ✅ Signature verification to detect tampering



## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Install required libraries:

```bash
pip install pycryptodome
