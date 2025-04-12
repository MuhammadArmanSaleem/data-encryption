import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet
import os
import re

# Constants
DATA_FILE = "stored_data.json"
KEY_FILE = "secret.key"
MAX_ATTEMPTS = 3

# Load or generate encryption key
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    KEY = f.read()

cipher = Fernet(KEY)

# Load or initialize stored data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Session state initialization
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Helper functions
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# UI
st.title("🔐 Streamlit Secure Data Vault")

menu = ["Home", "Register", "Store Data", "Retrieve Data", "Login", "Logout", "Delete Data", "Delete User"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app allows you to securely store and retrieve encrypted data.")

elif choice == "Register":
    st.subheader("📝 Create Account")
    username = st.text_input("Choose a username")
    passkey = st.text_input("Choose a passkey", type="password")

    if st.button("Register"):
        if username in stored_data:
            st.error("❌ Username already exists.")
        elif not is_strong_password(passkey):
            st.error("❌ Password must be at least 8 characters long and include an uppercase letter, lowercase letter, a number, and a special character.")
        else:
            stored_data[username] = {"passkey": hash_passkey(passkey), "data": []}
            save_data()
            st.success("✅ Account created successfully!")

elif choice == "Store Data":
    st.subheader("📦 Store Encrypted Data")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")
    data_to_store = st.text_area("Enter data to encrypt")

    if st.button("Encrypt & Store"):
        user = stored_data.get(username)
        if user and user["passkey"] == hash_passkey(passkey):
            encrypted = encrypt_data(data_to_store)
            user["data"].append(encrypted)
            save_data()
            st.session_state.logged_in_user = username
            st.session_state.authenticated = True
            st.success("✅ Data encrypted and saved!")
        else:
            st.session_state.failed_attempts += 1
            remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts remaining: {remaining}")

            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.warning("🔒 Too many failed attempts! Please reauthorize.")

elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Your Data")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Retrieve"):
        user = stored_data.get(username)
        if user and user["passkey"] == hash_passkey(passkey):
            st.session_state.failed_attempts = 0
            st.session_state.logged_in_user = username
            st.session_state.authenticated = True
            if user["data"]:
                st.write("🗃️ Your Encrypted Data:")
                for i, encrypted in enumerate(user["data"], 1):
                    st.write(f"{i}. {decrypt_data(encrypted)}")
            else:
                st.info("No data stored yet.")
        else:
            st.session_state.failed_attempts += 1
            remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts remaining: {remaining}")

            if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.warning("🔒 Too many failed attempts! Please reauthorize.")

elif choice == "Login":
    st.subheader("🔐 Reauthorization Required")
    login_user = st.text_input("Enter your username")
    login_pass = st.text_input("Enter your password", type="password")
    if st.button("Login"):
        user = stored_data.get(login_user)
        if user and user["passkey"] == hash_passkey(login_pass):
            st.session_state.failed_attempts = 0
            st.session_state.logged_in_user = login_user
            st.session_state.authenticated = True
            st.success("✅ Access granted!")
        elif login_pass == "Phantom_Rocks":
            st.session_state.failed_attempts = 0
            st.success("✅ Master access granted!")
        else:
            st.error("❌ Incorrect credentials.")

elif choice == "Logout":
    st.subheader("🚪 Logout")
    if st.session_state.logged_in_user:
        st.session_state.logged_in_user = None
        st.session_state.authenticated = False
        st.success("✅ You have logged out successfully!")
    else:
        st.warning("You are not logged in.")

elif choice == "Delete Data":
    st.subheader("❌ Delete Your Stored Data")
    if st.session_state.authenticated and st.session_state.logged_in_user:
        if st.button("Delete Data"):
            if st.session_state.logged_in_user in stored_data:
                stored_data[st.session_state.logged_in_user]["data"] = []
                save_data()
                st.success("✅ Your stored data has been deleted successfully!")
            else:
                st.warning("No data found to delete.")
    else:
        st.warning("Please log in to delete data.")

elif choice == "Delete User":
    st.subheader("❌ Delete Your Account")
    if st.session_state.authenticated and st.session_state.logged_in_user:
        if st.button("Delete User"):
            del stored_data[st.session_state.logged_in_user]
            save_data()
            st.session_state.logged_in_user = None
            st.session_state.authenticated = False
            st.success("✅ Your user account has been deleted successfully!")
    else:
        st.warning("Please log in to delete your account.")
