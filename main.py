import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
from datetime import datetime, timedelta
import os
import re

# ========== CONFIGURATION ==========
st.set_page_config(
    page_title="Secure Data Vault",
    page_icon="🔒",
    layout="centered"
)

# ========== SECURITY SETUP ==========
def load_key():
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

KEY = load_key()
cipher = Fernet(KEY)

# ========== DATA STORAGE ==========
def load_data():
    try:
        with open("secure_data.json", "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"users": {}, "vaults": {}}

def save_data(data):
    with open("secure_data.json", "w") as f:
        json.dump(data, f)

data = load_data()
users = data["users"]
vaults = data["vaults"]

failed_attempts = 0
lockout_until = None

# ========== SECURITY FUNCTIONS ==========
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    iterations = 100000
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations
    )
    return f"{salt}${iterations}${hashed.hex()}"

def verify_password(password, hashed_password):
    if not hashed_password:
        return False
    salt, iterations, stored_hash = hashed_password.split('$')
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        int(iterations)
    ).hex()
    return new_hash == stored_hash

def check_lockout():
    global lockout_until
    if lockout_until and datetime.now() < lockout_until:
        remaining_time = lockout_until - datetime.now()
        st.error(f"🔒 Account locked. Try again in {remaining_time.seconds//60}m {remaining_time.seconds%60}s")
        return True
    return False

def reset_lockout():
    global failed_attempts, lockout_until
    failed_attempts = 0
    lockout_until = None

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not re.search("[a-z]", password):
        return "Password must contain at least one lowercase letter"
    if not re.search("[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search("[0-9]", password):
        return "Password must contain at least one digit"
    if not re.search("[!@#$%^&*()_+=-]", password):
        return "Password must contain at least one special character"
    return None

# ========== STREAMLIT UI ==========
def home_page():
    st.title("🔒 Secure Data Vault")
    st.markdown("""
    Welcome to your personal secure data storage system. Store sensitive information 
    encrypted with military-grade algorithms and retrieve it only with your secret passkey.
    """)
    
    if 'username' not in st.session_state:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Login"):
                st.session_state.page = "login"
                st.rerun()
        with col2:
            if st.button("Sign Up"):
                st.session_state.page = "signup"
                st.rerun()
    else:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📥 Store New Data"):
                st.session_state.page = "store"
                st.rerun()
        with col2:
            if st.button("📤 Retrieve Data"):
                st.session_state.page = "retrieve"
                st.rerun()
        
        if st.button("🚪 Logout"):
            del st.session_state.username
            st.session_state.page = "home"
            st.rerun()

def login_page():
    st.title("🔑 Login")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if not username or not password:
            st.error("Both username and password are required!")
        elif username not in users:
            st.error("Username not found!")
        elif verify_password(password, users[username]["password"]):
            st.session_state.username = username
            st.session_state.page = "home"
            st.rerun()
        else:
            st.error("Incorrect password!")
    
    if st.button("🏠 Back to Home"):
        st.session_state.page = "home"
        st.rerun()

def signup_page():
    st.title("📝 Sign Up")
    
    username = st.text_input("Choose a Username")
    email = st.text_input("Email Address")
    password = st.text_input("Create Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Create Account"):
        if not all([username, email, password, confirm_password]):
            st.error("All fields are required!")
        elif password != confirm_password:
            st.error("Passwords don't match!")
        elif username in users:
            st.error("Username already exists!")
        else:
            password_error = validate_password(password)
            if password_error:
                st.error(password_error)
            else:
                users[username] = {
                    "email": email,
                    "password": hash_password(password),
                    "created_at": datetime.now().isoformat()
                }
                vaults[username] = {}
                save_data({"users": users, "vaults": vaults})
                st.success("Account created successfully! Please login.")
                st.session_state.page = "login"
                st.rerun()
    
    if st.button("🏠 Back to Home"):
        st.session_state.page = "home"
        st.rerun()

def store_page():
    if 'username' not in st.session_state:
        st.session_state.page = "login"
        st.rerun()
        return
    
    st.title("📥 Store Secure Data")
    
    data_id = st.text_input("Unique Identifier (e.g., 'my_password')")
    secret_data = st.text_area("Data to Encrypt", height=150)
    passkey = st.text_input("Encryption Passkey", type="password")
    confirm_passkey = st.text_input("Confirm Passkey", type="password")
    
    if st.button("Encrypt & Store"):
        if not all([data_id, secret_data, passkey, confirm_passkey]):
            st.error("All fields are required!")
        elif passkey != confirm_passkey:
            st.error("Passkeys don't match!")
        elif len(passkey) < 8:
            st.error("Passkey must be at least 8 characters")
        else:
            hashed_passkey = hash_password(passkey)
            encrypted_data = encrypt_data(secret_data)
            
            vaults[st.session_state.username][data_id] = {
                "encrypted_data": encrypted_data,
                "passkey_hash": hashed_passkey,
                "created_at": datetime.now().isoformat()
            }
            save_data({"users": users, "vaults": vaults})
            
            st.success("✅ Data stored securely!")
            st.code(f"ID: {data_id}\nEncrypted: {encrypted_data[:50]}...")
            st.balloons()
    
    if st.button("🏠 Return to Home"):
        st.session_state.page = "home"
        st.rerun()

def retrieve_page():
    if 'username' not in st.session_state:
        st.session_state.page = "login"
        st.rerun()
        return
    
    global failed_attempts, lockout_until
    
    st.title("📤 Retrieve Secure Data")
    
    if check_lockout():
        if st.button("🏠 Return to Home"):
            st.session_state.page = "home"
            st.rerun()
        return
    
    user_vault = vaults.get(st.session_state.username, {})
    data_id = st.selectbox("Select Data ID", options=list(user_vault.keys()))
    passkey = st.text_input("Enter Passkey", type="password")
    
    if st.button("Decrypt Data"):
        if not passkey:
            st.error("Passkey is required!")
            return
            
        record = user_vault.get(data_id)
        if not record:
            st.error("Invalid data ID!")
            return
            
        if verify_password(passkey, record["passkey_hash"]):
            reset_lockout()
            decrypted_data = decrypt_data(record["encrypted_data"])
            
            st.success("✅ Decryption Successful!")
            st.text_area("Decrypted Data", value=decrypted_data, height=200)
            
            created_at = datetime.fromisoformat(record["created_at"])
            st.caption(f"Stored on: {created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            failed_attempts += 1
            remaining_attempts = 3 - failed_attempts
            st.error(f"❌ Incorrect passkey! {remaining_attempts} attempts remaining")
            
            if failed_attempts >= 3:
                lockout_until = datetime.now() + timedelta(minutes=5)
                st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")
    
    if st.button("🏠 Return to Home"):
        st.session_state.page = "home"
        st.rerun()

# ========== MAIN APP ==========
def main():
    if 'page' not in st.session_state:
        st.session_state.page = "home"
    
    if st.session_state.page == "home":
        home_page()
    elif st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "signup":
        signup_page()
    elif st.session_state.page == "store":
        store_page()
    elif st.session_state.page == "retrieve":
        retrieve_page()

if __name__ == "__main__":
    if not os.path.exists("secret.key"):
        with open("secret.key", "wb") as f:
            f.write(Fernet.generate_key())
    main()