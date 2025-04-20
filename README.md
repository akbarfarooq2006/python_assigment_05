# Secure Data Encryption System

A secure web application built with **Streamlit** to store, retrieve, and manage encrypted data. This project provides user authentication, data encryption, and secure account management features, ensuring data privacy and security.

## 🚀 Project Overview
The **Secure Data Encryption System** is designed to allow users to securely store sensitive data using encryption. Users can register, log in, store encrypted data, retrieve it, download it, change their password, and delete their account. The application includes a CAPTCHA verification system to enhance security during critical actions like account deletion.

Developed as a Python project, it leverages Streamlit for the frontend and uses cryptographic libraries for secure data handling.

## ✨ Features
- **User Authentication**:
  - Register a new account with a username and password.
  - Log in securely with hashed password verification.
- **Data Encryption**:
  - Store sensitive data with a custom passkey using the Fernet encryption method.
  - Retrieve encrypted data by providing the correct passkey.
- **Account Management**:
  - Change password securely after verifying the old password.
  - Delete account with CAPTCHA verification to prevent unauthorized actions.
- **Data Download**:
  - Download all encrypted data as a JSON file.
- **Security Features**:
  - Passwords are hashed using SHA-256.
  - Image-based CAPTCHA for account deletion.
  - Session management to maintain user state across browser sessions.
- **User Interface**:
  - Clean and intuitive UI built with Streamlit.
  - Sidebar navigation for easy access to features.

## 📦 Installation
Follow these steps to set up the project on your local machine.

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Steps
1. **Clone the Repository** (if hosted on GitHub):
   ```bash
   git clone <https://github.com/akbarfarooq2006/python_assigment_05>
   cd secure-data-encryption-system
   ```
2. **Install Dependencies**:
   Install the required Python libraries using the following command:
   ```bash
   pip install streamlit cryptography Pillow numpy
   ```
3. **Run the Application**:
   Start the Streamlit server to run the app:
   ```bash
   streamlit run app.py
   ```
   The app will open in your default web browser at `http://localhost:8501`.

## 🛠️ Usage
1. **Register an Account**:
   - Go to the "Register" tab.
   - Enter a unique username and password, then click "Register".
2. **Log In**:
   - Go to the "Login" tab.
   - Enter your username and password, then click "Login".
3. **Store Data**:
   - Navigate to "Store Data" from the sidebar.
   - Enter a title, secret data, and passkey, then click "Encrypt & Save".
4. **Retrieve Data**:
   - Navigate to "Retrieve Data".
   - Select a title, enter the passkey, and click "Decrypt" to view your data.
5. **Change Password**:
   - Go to "Change Password".
   - Enter your old and new passwords, then click "Update Password".
6. **Delete Account**:
   - Navigate to "Delete Profile".
   - Confirm the action, enter your password, solve the CAPTCHA, and click "Delete My Profile".
7. **Download Data**:
   - Go to "Download data" to download your encrypted data as a JSON file.
8. **Log Out**:
   - Select "Logout" from the sidebar to end your session.

## 📂 File Structure
- `app.py`: Main application file containing the Streamlit code and logic.
- `data.json`: Stores encrypted user data.
- `user.json`: Stores user credentials (hashed passwords).
- `session.json`: Stores session state for persistence across browser sessions.

## 🧑‍💻 Technologies Used
- **Streamlit**: For building the web interface.
- **Cryptography**: For encrypting and decrypting data using Fernet.
- **Pillow (PIL)**: For generating image-based CAPTCHAs.
- **NumPy**: For array operations (used in CAPTCHA generation).
- **Hashlib**: For hashing passwords using SHA-256.
- **JSON**: For storing data persistently in files.

## 👨‍💻 Developer
- **Name**: Akbar Farooq
- **Email**: [akbarfarooq2006@gmail.com]
- **GitHub**: [https://github.com/akbarfarooq2006/]

## 📜 License
This project is licensed under the MIT License. Feel free to use and modify it as per your needs.