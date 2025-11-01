import json
import csv
import base64
import os
from pathlib import Path

def main ():
    print ("Starting FireFox password decryption...")
    
    profile_path = find_profile()
    if not profile_path:
        print("No profile found, exiting.")
        return
    
    print (f"Profile path being used: {profile_path}")
    login_data = read_login_data(profile_path)

    if login_data:
        login = login_data.get('logins', [])
        print (f"Found {len('logins')} saved logins.")

        examine_encrypted_data(login_data)
        decrypted_logins = decrypt_firefox_data(profile_path, login_data)

        if decrypted_logins:
            print("\n" + "="*50)
            print("Decrypted Logins:")
            print ("="*50)
            for i, login in enumerate(decrypted_logins, 1):
                print (f"Login {i}:")
                print (f"    Website: {login['hostname']}")
                print (f"    Username: {login['username']}")
                print (f"    Password: {login['password']}")
                print (f"    Times Used: {login['timesUsed']}")

        
    else:
        print("Failed to read data login")
    pass


def find_profile():
    """Find the default Firefox profile directory."""
    home = Path.home()

    possible_paths = []

    # Common paths by OS
    if os.name == 'nt': # For Windows
        possible_paths.append( home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles")
    elif os.name == 'posix': # For Linux and MacOS
        possible_paths.append( home / ".mozilla" / "firefox") # Linux
        possible_paths.append( home / "Library" / "Application Support" / "Firefox" / "Profiles") # MacOS

    # look for profile directories
    for base_path in possible_paths:
        if base_path.exists():
            # find dir that look like profiles
            for item in base_path.iterdir():
                if item.is_dir() and '.' in item.name: # profile dirs contain a dot
                    # Check if it has the key files we need
                    if (item/ "key4.db").exists() and (item / "logins.json").exists():
                        print (f"Found Firefox profile at: {item}")
                        return item
                    
    print ("No Firefox profile found.")
    return None


def read_login_data (profile_path):
    """"Read the logins.json file and return the data"""
    try:
        logins_file = Path(profile_path) / "logins.json"
        print (f"Looking for logins.json at: {logins_file}")

        if not logins_file.exists():
            print ("logins.json file does not exist.")
            return None
        print ("login files found")

        # Read file
        with open(logins_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print ("Successfully read logins.json")
            return data

    except Exception as e:
        print (f"Error reading login data: {e}")
        return None


def examine_encrypted_data (login_data):
    """Let's see ehat the encrypted data looks like"""
    logins = login_data.get('logins', [])
    if logins:
        first_login = logins[0]
        print("Encrypted data sample.")
        print(f"Username (encrypted): {first_login.get('encryptedUsername', '')[:50]}...")
        print(f"Password (encrypted): {first_login.get('encryptedPassword', '')[:50]}...")
        print(f"Hostname: {first_login.get('hostname', '')}")

        # See if it looks like base64
        encrypted_user = first_login.get('encryptedUsername', '')
        encrypted_pass = first_login.get('encryptedPassword', '')

        if encrypted_user:
            print (f"Username length: {len(encrypted_user)} chars")
        if encrypted_pass:
            print (f"Password length: {len(encrypted_pass)} chars")

def decrypt_firefox_data (profile_path, login_data):
    """
    Decrpyt the firefoc login data
    returns a list of dict with decrypted data
    """

    decrypted_logins = []

    print ("\n STARTING DECRYPTION PROCESS.......")

    # get key
    key = get_encryption_key(profile_path)
    if not key:
        print ("Failed to get encryption key, cannot decrypt data.")
        return []
    print ("Encryption key obtained successfully.")

    # loop through each login and dycrypt
    logins = login_data.get('logins', [])
    for i, login in enumerate(logins):
        print (f"Decrypting login {i+1}/{len(logins)}...")

        enc_username = login.get('encryptedUsername', '')
        enc_password = login.get('encryptedPassword', '')

        dec_username = decrypt_value(enc_username, key)
        dec_password = decrypt_value(enc_password, key)

        decrypted_login = {
            'hostname': login.get('hostname', ''),
            'username': dec_username,
            'password': dec_password,
            'timesUsed': login.get('timesUsed', 0),
            'timeCreated': login.get('timeCreated', 0),
        }
        decrypted_logins.append(decrypted_login)

        print (f"Successfully decrypted {len(decrypted_logins)} logins")
        return decrypted_logins
    

def decrypt_value (enc_value, key):
    """
    Decrypt a single encrypted value using the provided key
    """
    try:
        if not enc_value:
            return ""
        print (f"     decrypting value (length: {len(enc_value)})...")

        # for now return placeholder
        return f"<decrypted_value>"

    except Exception as e:
        return f"<decryption_error: {str(e)}>"


def get_encryption_key(profile_path):
    """
    Retrieve the encryption key from key4.db
    """
    key_file = Path(profile_path) / "key4.db"

    if not key_file.exists():
        print ("key4.db file does not exist.")
        return None
    
    try:
        print ("Found key4.db, attempting to retrieve encryption key...")


        ## for now return placeholder
        placeholder_key = b"placeholder_key_32_bytes!!"
        print ("Using placeholder key for now")
        return placeholder_key

    except Exception as e:
        print (f"Error retrieving encryption key: {e}")
        return None

if __name__ == "__main__":
    main()