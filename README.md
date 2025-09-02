# 🔐 File Encryptor/Decryptor

A desktop application for securely **encrypting and decrypting your files** using strong password-based encryption. Protect sensitive files from unauthorized access while keeping the workflow simple and user-friendly.

---

## 🛠 Features

- AES 256-bit Encryption (via Fernet) using a password-derived key
- Password Strength Indicator to encourage secure passwords
- Encrypt & Decrypt any file easily
- Automatic file versioning to prevent overwriting files
- Encrypted files saved next to the original for convenience
- User-friendly GUI with progress bar, status messages, and easy file selection
- Clear Fields & Open Folder options for better usability
- Handles large files efficiently with chunked encryption

---

## 💻 Screenshots

**Main window showing file selection and password entry**

![Main Window](assets/main_window.png)

**Encryption in progress with progress bar and status messages**

![Encryption Progress](assets/encryption_progress.png)

> *(You can replace these with actual screenshots in an `assets/` folder.)*

---

## 🚀 How to Use

1. **Clone the repository**

```bash
git clone https://github.com/<your-username>/File-Encryptor-Decryptor.git
cd File-Encryptor-Decryptor

2.Install dependencies

pip install -r requirements.txt

3.Run the application

python main.py

4.Encrypt a file

Click Browse to select a file.

Enter a password and confirm it.

Click Encrypt.

The encrypted file will be saved next to the original with a .encrypted extension.

Decrypt a file

Click Browse to select an encrypted file (.encrypted).

Enter the password used for encryption.

Click Decrypt.

The decrypted file will be saved next to the encrypted file.

🔐 Security

Uses PBKDF2HMAC with 480,000 iterations to derive a strong key from your password

Unique salt is generated per file and stored in the encrypted file header

Encryption and decryption use the Fernet symmetric algorithm from the cryptography library

⚡ Tech Stack

Python 3.11+

Tkinter for GUI

cryptography library for encryption and decryption

🧑‍💻 Contributions

Contributions are welcome! Feel free to:

Add new features (e.g., drag-and-drop support)

Improve GUI styling

Optimize for very large files

Report bugs or issues

📄 License

This project is MIT Licensed. See LICENSE for more details.

⭐ Acknowledgements

Python Cryptography Library

Tkinter Documentation


---

### 3️⃣ Add screenshots (optional but recommended)

- Create a folder called `assets` in your project folder.
- Save screenshots inside it with names matching your Markdown links, e.g., `main_window.png` and `encryption_progress.png`.
- The images will now appear correctly in GitHub.

---

### 4️⃣ Preview it on GitHub

Once you push your project to GitHub, GitHub will automatically render `README.md` in a **clean, formatted style**.

---

If you want, I can **create a ready-to-push folder structure with README, .gitignore, requirements.txt, and a placeholder assets folder** so you can just push it directly to GitHub.

Do you want me to do that?


