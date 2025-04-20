import streamlit as st
import hashlib
import json
import os
import time
import random
import string
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode




DATA_FILE = "data.json"
USERS_FILE = "user.json"
SESSION_FILE = "session.json"  # Nayi file jo session state store karegi

# File handling functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            try:
                data = json.load(file)
                return data
            except json.decoder.JSONDecodeError:
                print("File khaali hai ya format sahi nahi hai.")
                return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as file:
            try:
                data = json.load(file)
                return data
            except json.decoder.JSONDecodeError:
                print("File khaali hai ya format sahi nahi hai.")
                return {}      

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# Session state ko file mein store/load karne ke functions
def load_session():
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, "r") as file:
            try:
                data = json.load(file)
                return data
            except json.decoder.JSONDecodeError:
                print("Session file khaali hai ya format sahi nahi hai.")
                return {}
    return {}

def save_session(session_data):
    with open(SESSION_FILE, "w") as f:
        json.dump(session_data, f, indent=4)

# Initial data load
stored_data = load_data()
users_data = load_users()
session_data = load_session()






if "stored_data" not in st.session_state:
    st.session_state.stored_data = stored_data
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = session_data.get("is_logged_in", False)  
if "current_user" not in st.session_state:
    st.session_state.current_user = session_data.get("current_user", None)
if "page" not in st.session_state:
    st.session_state.page = session_data.get("page", "Login")
# if "selected_page" not in st.session_state:
#         st.session_state.selected_page = session_data.get("page", "Home")
    
    
# generate cipher from passkey
def generate_cipher(passkey):
    salt = b'streamlit-salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(passkey.encode()))
    return Fernet(key)


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text, passkey):
    cipher = generate_cipher(passkey)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    try:
        cipher = generate_cipher(passkey)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None
                  
# def generate_captcha():
#     characters = string.ascii_letters + string.digits
#     captcha_code = ''.join(random.choice(characters) for _ in range(6))
#     return captcha_code

# Generate an image-based CAPTCHA
# Generate an image-based CAPTCHA
def generate_image_captcha():
    # Generate a random 6-character code
    characters = string.ascii_letters + string.digits
    captcha_code = ''.join(random.choice(characters) for _ in range(6))
    
    # Create an image
    width, height = 150, 50
    image = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(image)
    
    # Use a default font (you can replace with a custom font if available)
    try:
        font = ImageFont.truetype("arial.ttf", 30)
    except:
        font = ImageFont.load_default()  # Default font
    
    # Calculate text size using textbbox
    # textbbox returns (left, top, right, bottom) coordinates
    bbox = draw.textbbox((0, 0), captcha_code, font=font)
    text_width = bbox[2] - bbox[0]  # right - left
    text_height = bbox[3] - bbox[1]  # bottom - top
    
    # Add distorted text
    x = (width - text_width) // 2
    y = (height - text_height) // 2
    
    for i, char in enumerate(captcha_code):
        # Add some distortion to each character
        offset_x = x + i * (text_width // len(captcha_code))
        offset_y = y + random.randint(-5, 5)  # Random vertical offset
        draw.text((offset_x, offset_y), char, fill="black", font=font)
    
    # Add noise (random lines and dots)
    for _ in range(20):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line((x1, y1, x2, y2), fill="gray", width=1)
    
    for _ in range(50):
        x, y = random.randint(0, width), random.randint(0, height)
        draw.point((x, y), fill="gray")
    
    # Convert image to bytes for Streamlit
    buf = BytesIO()
    image.save(buf, format="PNG")
    byte_im = buf.getvalue()
    
    return captcha_code, byte_im

    
    
st.set_page_config(page_title="Secure Data", page_icon="🛡️", initial_sidebar_state="collapsed")
st.title("🔐Secure Data Encryption System") #🛡️
st.caption("Developed by Akbar Farooq")

if not st.session_state.is_logged_in and st.session_state.page=="Login":
    auth_tab = st.radio("Login or Register", ["Login", "Register"], horizontal=True)

    if auth_tab == "Register":
        st.subheader("💊 Create New Account")
        new_user = st.text_input("👤 Username")
        new_pass = st.text_input("🔑 Password", type="password")
        
        if st.button("📝 Register"):
            if new_user in users_data:
                st.error("❌ username is already exist try other")
            elif new_pass and new_user:
                users_data[new_user] = hash_passkey(new_pass)
                save_users(users_data)
                st.success("✅ Registered successfully! You can now login.")
                st.info("👉 Go to the login with this username and password")
                st.balloons()
            else:
                st.warning("⚠️ Please enter both username and password.")
    
    elif auth_tab == "Login":
        st.subheader("💊 Login to Account")
        new_user = st.text_input("👤 Username")
        new_pass = st.text_input("🔑 Password", type="password")
        
        hash_new_pass = hash_passkey(new_pass)
        # st.write(users_data)
        if st.button("🔓 Login"):
            if new_user in users_data and hash_new_pass== users_data[new_user]:
                st.session_state.current_user = new_user
                st.session_state.is_logged_in = True
                st.session_state.page = "Home"
                st.session_state.selected_page = "Home"
                session_data = {
                    "is_logged_in": True,
                    "current_user": new_user,
                    "page": "Home"
                }
                save_session(session_data)
                
                with st.spinner("Please wait..."):
                    time.sleep(3)  # 3 seconds ka delay
                st.success(f"✅ Login succesfullly, Welcome {new_user}")
                time.sleep(2)
                # st.write(st.session_state)
                st.rerun()
                # st.success("✅ Login succesfullly")
            elif new_user not in users_data:
                st.error("❌ Enter the correct user name")
            elif hash_new_pass != users_data[new_user]:
                st.error("❌ Enter the correct passkey")
                
                

                

            
if st.session_state.is_logged_in == True:
    menu = ["Home", "Store Data", "Retrieve Data", "Download data", "Change Password", "Delete Profile", "Logout"]

   
    # Selectbox ko st.session_state.selected_page ke saath sync karo
    choice = st.sidebar.selectbox("Navigate", menu, index=menu.index(st.session_state.page))

    st.session_state.page = choice
    # updeate in session file
    session_data["page"] = choice
    save_session(session_data)

# Home
    if choice == "Home" and st.session_state.page == "Home":
        session_data["page"] = choice
        save_session(session_data)
        st.subheader("🏠 Welcome to Your Secure Data store")
        st.markdown("Use the sidebar to store or retrieve your encrypted data.")
        # st.info(st.session_state)

# Store Data
    elif choice == "Store Data" and st.session_state.page == "Store Data":
        st.subheader("🔒 Store Encrypted Data")
        
        #  take input to store data
        title = st.text_input("📜 Title for Your Secret", placeholder="Enter a title for your data")
        user_data = st.text_area("📝 Enter Secret Data:", placeholder="Enter your secret data here")
        passkey = st.text_input("🔑 Create Passkey:", type="password", placeholder="Create a passkey for encryption")
        
        # Encrypt & Save button
        submit_button = st.button("🔐 Encrypt & Save")
        if submit_button:
            if not title or not user_data or not passkey:
                st.error("❌ Please fill all fields.")
            else:
                # Encrypt data
                encrypted_data = encrypt_data(user_data, passkey)
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                username = st.session_state.current_user
                if username not in st.session_state.stored_data:
                    st.session_state.stored_data[username] = {}
                st.session_state.stored_data[username][title] = {
                    "encrypted": encrypted_data,
                    "passkey": hash_passkey(passkey),
                    "timestamp": timestamp
                }
                # Save to file
                save_data(st.session_state.stored_data)
                # Success message
                with st.spinner("Encrypting and saving..."):
                    time.sleep(1)
                st.success(f"✅ Data '{title}' encrypted and saved successfully!")
                # st.success("✅ Data encrypted and saved!")
                st.balloons()
                with st.expander("📆 Encrypted Text (click to view)"):
                    st.code(encrypted_data, language="text")
 
                #   
    
    
# Retrive Data
    elif choice == "Retrieve Data" and st.session_state.page == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        
        # GET   array of key of data
        username = session_data.get("current_user","None")
        data_title= stored_data[username].keys()
        # use that array to show the option
        selected_title = st.selectbox("📁 Select a Title to Decrypt",data_title )  # Placeholder option
        passkey = st.text_input("🔑 Enter Passkey:", type="password", placeholder="")
        # Decrypt button
        if st.button("🎉 Decrypt"):
            if selected_title and passkey:
                if selected_title not in stored_data[username]:
                    st.error("❌ Title not found")
                elif stored_data[username][selected_title]["passkey"] !=hash_passkey(passkey):
                    st.error("❌ Passkey not match")
                else:
                    encrypt_data2= stored_data[username][selected_title]["encrypted"]
                    encrypt_time= stored_data[username][selected_title]["timestamp"]
                    decrypt_text = decrypt_data(encrypt_data2,passkey)
                    st.success("✅ Decrypted Data:")
                    st.code(decrypt_text, language="text")
                    st.write("⌚ Encrypted Time")
                    st.code(encrypt_time, language="text")                    
            else:
                st.error("❌ Please fill all fields.")
        
# Download Data  
    elif choice == "Download data" and st.session_state.page == "Download data":
        st.subheader("📥 Download Your Encrypted Data")
        username = session_data["current_user"]
        # Check if user has any data
        if username in st.session_state.stored_data and st.session_state.stored_data[username]:
            data_of_specific_user = st.session_state.stored_data[username]  # Sirf current user ka data
            # Convert the user data to JSON string
            json_data = json.dumps(data_of_specific_user, indent=4)
            # Download button to download the JSON file
            st.download_button(
                label="⬇️ Download as JSON",
                data=json_data,
                file_name=f"{username}_data.json",
                mime="application/json"
            )
        else:
            st.warning("⚠️ No data found for this user to download.")


# Delete Profile
    elif choice == "Delete Profile" and st.session_state.page == "Delete Profile":
        st.subheader("🗑️ Delete Account")

        # Checkbox
        understand_action = st.checkbox("✅ I understand that this action is irreversible.")

        # Password input field
        password = st.text_input("🔑 Confirm Password", type="password", placeholder="")

        # CAPTCHA
        if "captcha_code" not in st.session_state or "captcha_image" not in st.session_state:
            captcha_code, captcha_image = generate_image_captcha()
            st.session_state.captcha_code = captcha_code
            st.session_state.captcha_image = captcha_image

        st.write("🤖 CAPTCHA Verification")
        st.image(st.session_state.captcha_image, caption="CAPTCHA Image", use_container_width=False)
        captcha_input = st.text_input("📝 Enter the CAPTCHA code above:", placeholder="")

        # Delete button
        if st.button("🗑️ Delete My Profile"):
            if not understand_action:
                st.error("❌ Please confirm that you understand this action is irreversible.")
            elif not password:
                st.error("❌ Please enter your password.")
            elif not captcha_input:
                st.error("❌ Please enter the CAPTCHA code.")
            else:
                # Password verification
                username = st.session_state.current_user
                hashed_input_password = hash_passkey(password)
                if hashed_input_password != users_data.get(username):
                    st.error("❌ Incorrect password.")
                # CAPTCHA verification
                elif captcha_input != st.session_state.captcha_code:
                    st.error("❌ Incorrect CAPTCHA code.")
                    # Generate new CAPTCHA on failure
                    captcha_code, captcha_image = generate_image_captcha()
                    st.session_state.captcha_code = captcha_code
                    st.session_state.captcha_image = captcha_image
                else:
                    # Delete user data and account
                    if username in st.session_state.stored_data:
                        del st.session_state.stored_data[username]
                        save_data(st.session_state.stored_data)
                    if username in users_data:
                        del users_data[username]
                        save_users(users_data)

                    # Log out the user
                    st.session_state.current_user = None
                    st.session_state.is_logged_in = False
                    st.session_state.page = "Login"
                    st.session_state.selected_page = "Login"
                    st.session_state.navigate_selectbox_key = "Login"
                    session_data = {
                        "is_logged_in": False,
                        "current_user": None,
                        "page": "Login"
                    }
                    save_session(session_data)
                    st.success("✅ Account deleted successfully!")
                    st.rerun() 
# change password
    elif choice == "Change Password" and st.session_state.page == "Change Password":
        st.subheader("🔑 Change Password")
        old_password = st.text_input("🔒 Old Password", type="password", placeholder="")
        new_password = st.text_input("🆕 New Password", type="password", placeholder="")
        
        # Update Password button
        if st.button("🔄 Update Password"):
            if not old_password:
                st.error("❌ Please enter your old password.")
            elif not new_password:
                st.error("❌ Please enter a new password.")
            else:
                username = st.session_state.current_user
                hashed_old_password = hash_passkey(old_password)
                # Verify old password
                if hashed_old_password != users_data.get(username):
                    st.error("❌ Incorrect old password.")
                else:
                    # Update password
                    users_data[username] = hash_passkey(new_password)
                    save_users(users_data)
                    st.success("✅ Password updated successfully!")
                    # Log out the user after password change
                    st.session_state.current_user = None
                    st.session_state.is_logged_in = False
                    st.session_state.page = "Login"
                    session_data = {
                        "is_logged_in": False,
                        "current_user": None,
                        "page": "Login"
                    }
                    save_session(session_data)
                    st.rerun()
# Logout  
    elif choice == "Logout" and st.session_state.page == "Logout":
        session_data["page"] = choice
        save_session(session_data)
        
        st.session_state.current_user = None
        st.session_state.is_logged_in = False
        st.session_state.page = "Login"
        session_data = {
            "is_logged_in": False,
            "current_user": None,
            "page": "Login"
        }
        save_session(session_data)
        st.rerun()
        
    
        











