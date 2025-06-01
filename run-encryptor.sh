#!/bin/bash

echo "Starting encryptor"
echo

if [ ! -f "./encryptor" ]; then
    echo "Error: encryptor executable not found in the current directory."
    echo "Please make sure the encryptor binary is in the same folder as this script."
    echo
    read -p "Press Enter to exit..."
    exit 1
fi

chmod +x ./encryptor

./encryptor

if [ $? -ne 0 ]; then
    echo
    echo "encryptor encountered an error."
    read -p "Press Enter to exit..."
fi 