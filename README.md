# 🔐 AuthTerminal: Encrypted 2FA Authenticator for your Terminal

A command-line (CLI) tool for managing your two-factor authentication (2FA / TOTP) codes right in your terminal.

Your secrets are stored in a local, strongly encrypted file protected by a master password that only you know.

## ✨ Features

* **Encrypted Vault:** Your 2FA secrets are saved in a local file, strongly encrypted using AES (via Fernet).
* **Master Password:** No action (viewing, importing) can be performed without the password.
* **Dynamic Display:** Shows your codes in a clean, auto-aligning list.
* **Auto-Refresh:** Codes and the time bar update in real-time every second.
* **Simple Import:** Easily add new accounts from a `.txt` file containing `otpauth://` URIs.
* **Secure Management:** Includes a dedicated command to securely change your master password.

---

## 🛠️ Installation & Setup

Follow these steps to install and configure the tool on your machine.

### 1. Clone the Repository

Open your terminal and clone this repository (`AuthTerminal`) to your desired folder:

```bash
git clone [https://github.com/littleg0d/AuthTerminal.git](https://github.com/littleg0d/AuthTerminal.git)
cd AuthTerminal



2. Install Dependencies

Dependencies are already listed in requirements.txt.
Install them with:

pip install -r requirements.txt


You’re now ready to use AuthTerminal ✅

🚀 Usage

Depending on your system, you may need to use python3 auth.py or py auth.py instead of python auth.py.

🗝️ 1. First-Time Setup (Create Encrypted Vault)

Before viewing any codes, you must import your accounts to create your encrypted vault.

Create a .txt file (e.g. my_keys.txt) with your otpauth:// URIs, one per line.

Run the import command:

python auth.py importar my_keys.txt


The script will:

Ask you to create a master password.

Import your accounts and encrypt them into a new file secrets.json.

👀 2. View Your 2FA Codes

Once you have imported your secrets, view your codes with:

python auth.py


You’ll be prompted for your master password.

The screen will show a real-time list of your codes with a refreshing timer bar.

Press Ctrl + C to exit the viewer.

➕ 3. Import More Accounts

To add new accounts later:

python auth.py importar another_file.txt


The tool unlocks your vault using your master password.

New secrets are added; duplicates are automatically ignored.

The vault is re-encrypted and saved.

🔄 4. Change Your Master Password

If you want to change your master password:

python auth.py cambiarpass


You’ll be prompted to:

Enter your current password.

Enter and confirm your new password.

Your vault will be re-encrypted with the new password.
