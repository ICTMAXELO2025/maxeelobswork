#!/usr/bin/env python3
"""
Setup script for Maxelo Work Management System
"""

import os
import subprocess
import sys

def run_command(command):
    """Run a shell command and return success status"""
    try:
        result = subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(f"Error: {e}")
        return False

def setup_environment():
    """Setup the development environment"""
    print("🚀 Setting up Maxelo Work Management System...")
    
    # Check if Python is installed
    if not run_command("python --version"):
        print("❌ Python is not installed or not in PATH")
        return False
    
    # Create virtual environment
    print("📦 Creating virtual environment...")
    if not run_command("python -m venv venv"):
        return False
    
    # Activate virtual environment and install dependencies
    print("📥 Installing dependencies...")
    
    if sys.platform == "win32":
        # Windows
        pip_cmd = "venv\\Scripts\\pip"
        python_cmd = "venv\\Scripts\\python"
    else:
        # macOS/Linux
        pip_cmd = "venv/bin/pip"
        python_cmd = "venv/bin/python"
    
    # Upgrade pip
    run_command(f"{pip_cmd} install --upgrade pip")
    
    # Install requirements
    if not run_command(f"{pip_cmd} install -r requirements.txt"):
        return False
    
    print("✅ Setup completed successfully!")
    print("\n🎯 Next steps:")
    print("1. Make sure PostgreSQL is running")
    print("2. Update your .env file with correct database credentials")
    print("3. Run: python app.py")
    print("4. Open http://localhost:5000 in your browser")
    
    return True

if __name__ == "__main__":
    setup_environment()