# AX-X a browser cookies and password hervester

This tools copies the two files where user session passwords are stored

1. key4.db - Contains encryption keys
2. logins.json - Contains encrypted password + metadata
3. Uses AES encryption in CBC mode

## Decryption process steps

1. Extract master key from key4.db
2. Read encrypted passwords from logins.json
3. Decrypt each password using AES-CBC
4. Save decrypted data to file

## Key libraries needed

1. py
2. lz4 - for session data decompression
3. csv - for saving as CSV
4. json - For parsing Firefox data

## WARNING

This is meant for eduactional purposes and i am not responsible for any damage caused by this script.