#!/bin/bash
set -e

echo "Initializing Kinetix environment..."

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
fi

# Activate venv and install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -e .

echo "Environment setup complete."
