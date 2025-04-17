import streamlit as st
import hashlib
from cryptography.fernet import Fernet


# Generate a key (should be saved in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory "database"
users_data = {}  # {"username": {"passkey": "hashed_passkey", "data": [encrypted1, encrypted2]}}
session_state = st.session_state

if "is_logged_in" not in session_state:
    session_state.is_logged_in = False
if "username" not in session_state:
    session_state.username = ""
if "failed_attempts" not in session_state:
    session_state.failed_attempts = 0

# Utils
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ---------------------- UI Flow ----------------------
def login_page():
    st.title("🔐 Secure Login")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Login"):
        if username in users_data and users_data[username]["passkey"] == hash_passkey(passkey):
            session_state.is_logged_in = True
            session_state.username = username
            session_state.failed_attempts = 0
            st.success("✅ Logged in successfully!")
            st.experimental_rerun()
        else:
            session_state.failed_attempts += 1
            st.error(f"❌ Invalid credentials! Attempts left: {3 - session_state.failed_attempts}")
            if session_state.failed_attempts >= 3:
                st.warning("🔒 Too many failed attempts. Please restart the app.")
                st.stop()

def register_user():
    st.subheader("📝 Register New User")
    new_user = st.text_input("Create Username")
    new_pass = st.text_input("Create Passkey", type="password")
    if st.button("Register"):
        if new_user and new_pass:
            if new_user in users_data:
                st.error("⚠️ Username already exists!")
            else:
                users_data[new_user] = {"passkey": hash_passkey(new_pass), "data": []}
                st.success("✅ User registered! Now login.")
        else:
            st.warning("Both fields are required.")

def dashboard():
    st.title(f"🔓 Welcome, {session_state.username}")
    menu = st.sidebar.radio("Choose an action:", ["Store Data", "Retrieve Data", "Logout"])

    if menu == "Store Data":
        st.subheader("🧾 Store Encrypted Data")
        data_input = st.text_area("Enter text to encrypt and store:")
        if st.button("Encrypt & Save"):
            if data_input:
                encrypted = encrypt_data(data_input)
                users_data[session_state.username]["data"].append(encrypted)
                st.success("✅ Data encrypted and saved.")
            else:
                st.warning("Please enter some text.")

    elif menu == "Retrieve Data":
        st.subheader("📥 Your Stored Data")
        stored = users_data[session_state.username]["data"]
        if not stored:
            st.info("You have no stored data.")
        else:
            for idx, enc in enumerate(stored):
                if st.button(f"Decrypt Entry {idx+1}"):
                    decrypted = decrypt_data(enc)
                    st.success(f"Decrypted: {decrypted}")

    elif menu == "Logout":
        session_state.is_logged_in = False
        session_state.username = ""
        st.success("👋 Logged out.")
        st.experimental_rerun()

# ---------------------- App Entry ----------------------

st.sidebar.title("Navigation")
nav = st.sidebar.selectbox("Go to", ["Login", "Register"])

if session_state.is_logged_in:
    dashboard()
else:
    if nav == "Login":
        login_page()
    elif nav == "Register":
        register_user()
