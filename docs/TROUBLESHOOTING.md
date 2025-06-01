## Guide & Troubleshooting

### **Where are my security keys?**

They're automatically created as `encryptor.key`, `encryptor.pub` (public), and `encryptor.kyber` in the same folder as the program.

### **What's the difference between my master password and file protection passwords?**

- **Master Password**: Never share this. Affects ALL your encrypted data. If you forget this password, you lose access to everything you've ever encrypted with this program. 
- **Protection Password**: This is what you share with others to let them decrypt files/texts you've sent them. Protects only one specific file or text. Each encryption can have a different protection password. If you forget a protection password, you only lose access to that specific encrypted item, not everything else. 

### **What if I forget my master password?**

Unfortunately, there is no way to recover the master password, and there is no way to recover your encrypted data. You need to reinstall the program in order to keep using it for new files/texts.

### **What if I forget my file protection password?**

Unfortunately, there's no way to recover your files/texts without the protection password, and there's no way to recover the data it was used to encrypt. But the protection password is specific to each protection, so it only affects the specific protection that it was used for.

### **How can I share protected files with others?**

You should send them:
- The `.encrypted` file (in your original file's directory)
- Your `encryptor.pub` file (in the program's directory) 
- The file protection password (**NOT your master password!**)

**Important**: They only need your `encryptor.pub` file for sharing. The `encryptor.key` and `encryptor.kyber` files should never be shared.

### **How can I share protected text with others?**

**On Windows:**
1. When you protect text, it's automatically saved to a file (e.g., `protected_1234567890.txt`)
2. Send them the file created by the program
3. Share the protection password (**NOT your master password!**)
4. They use Option 4 and load from the file

**On macOS/Linux:**
1. When you protect text, you can choose to save to file or copy to clipboard
2. If using file: Send them the file + protection password
3. If using clipboard/display: Copy the Base64 text and send it + protection password
4. They use Option 4 with their preferred input method

### **What does the other person need to do to decrypt a shared file or text?**

The recipient needs to:
1. **Have the encryptor program** - Download it the same way you did
2. **Replace their public key** - Copy your `encryptor.pub` file into their program folder (overwrite their existing `encryptor.pub` after running the program once)
3. **Run the program** and choose the appropriate option
4. **Enter the path/text** according to their platform capabilities
5. **Enter the protection password** you shared with them (**NOT your master password!**)
6. **Done!** - The original content will be restored

**Important**: They need YOUR `encryptor.pub` file, not their own, because the content was protected with your keys. They don't need your master password - only the protection password.

### **Why can't I paste encrypted text on Windows?**

Windows console has strict limitations on paste operations. Encrypted text includes:
- Digital signatures (~2-3KB overhead)
- Encryption metadata (~200 bytes)  
- Base64 encoding (+33% size increase)

This means even "hello" becomes ~4-5KB when encrypted, exceeding Windows paste limits. File-based approach is more reliable for all content sizes.

### **What if I delete `encryptor.key` and/or `encryptor.pub` files?**

This depends on which files you delete:
- **If you delete `encryptor.key`**: You won't be able to protect new files, but you can still unprotect existing files if you have `encryptor.pub`
- **If you delete `encryptor.pub`**: You won't be able to unprotect existing files, but you can still protect new files if you have `encryptor.key` and `encryptor.kyber`
- **If you delete `encryptor.kyber`**: You won't be able to decrypt any existing encrypted content, but you can protect/unprotect new content (new encryption keys will be generated)
- **If you delete all key files**: You can protect new files (new keys will be created), but you'll lose access to all previously encrypted files permanently
- **Fresh start**: You can always delete the old tool and download a fresh copy, or just run the existing tool again - it will automatically create new keys and work perfectly for protecting new files
- **Important**: Old encrypted files will remain permanently inaccessible without the original keys, but you can start protecting new files immediately
- **Solution**: Always keep backups of all three key files in a safe place.

### **Does it delete the original files once you encrypt them?**

No, the original file remains untouched, and a new locked version is created.

### **Is my master password stored anywhere?**

No, your master password is never stored. It's only used to encrypt/decrypt your private key in memory when needed.

### **What if I move to a new PC?**

To use your existing encrypted files on a new PC:
1. **Install encryptor**: Download and install the program on the new PC
2. **Remember your master password**: You'll need the same master password you used on the old PC
3. **Copy your key files**: Transfer `encryptor.key`, `encryptor.pub`, and `encryptor.kyber` from your old PC to the new PC (same folder as the encryptor program)
4. **Done**: You can now decrypt all your existing files and create new ones

**Important**: 
- Without your original key files, you cannot decrypt any previously encrypted content
- If you forget to backup your keys before switching PCs, all encrypted content becomes permanently inaccessible
- Always backup your `encryptor.key`, `encryptor.pub`, and `encryptor.kyber` files to a secure location before moving PCs

### **Should I keep the protected files secret?**

**Protected files (.encrypted files or encrypted text)**: These are designed to be shared and don't need to be kept secret. The security comes from:
- The protection password (which you share separately)
- The recipient needing your public key (`encryptor.pub`)

However, it's still good practice to:
- Not make them publicly available on the internet
- Share them only with intended recipients
- Use secure channels when possible

**What you MUST keep secret**:
- Your **master password** (never share this with anyone)
- Your **`encryptor.key` file** (your private signing key - keep this secure and backed up)
- Your **`encryptor.kyber` file** (your encryption keys - keep this secure and backed up)
- **Protection passwords** (only share with intended recipients)

**What you can safely share**:
- **`encryptor.pub` file** (your public key - recipients need this)
- **Protected .encrypted files** (these are useless without the protection password and your public key)
- **Encrypted text output** (same as protected files)

### **What should I copy when the program shows protected text? (macOS/Linux only)**

You can copy either:
- Just the Base64 encoded text between the `---` lines, OR
- The entire block including the header/footer lines

The program automatically handles both formats when decrypting, so don't worry about being precise with your selection.