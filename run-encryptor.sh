#!/bin/bash

echo "Starting Encryptor - Secure File Protection..."
echo

# Check if the executable exists
if [ ! -f "./encryptor" ]; then
    echo "Error: encryptor executable not found in the current directory."
    echo "Please make sure the encryptor binary is in the same folder as this script."
    echo
    read -p "Press Enter to exit..."
    exit 1
fi

# Make sure it's executable
chmod +x ./encryptor

# Run the encryptor
./encryptor

# Check if there was an error
if [ $? -ne 0 ]; then
    echo
    echo "Encryptor encountered an error."
    read -p "Press Enter to exit..."
fi 