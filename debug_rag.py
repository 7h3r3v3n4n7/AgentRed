#!/usr/bin/env python3
"""
Debug script for RAG functionality
"""

import os
import sys

# Set debug environment variable
os.environ['DEBUG'] = '1'

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

def debug_print(*args, **kwargs):
    """Print debug messages"""
    print("[DEBUG]", *args, **kwargs)

def test_rag_step_by_step():
    """Test RAG system step by step"""
    print("🔍 Testing RAG system step by step...")
    
    # Test 1: Check if scans directory exists
    scans_dir = "scans"
    debug_print(f"Checking scans directory: {scans_dir}")
    if os.path.exists(scans_dir):
        debug_print("Scans directory exists")
    else:
        debug_print("Scans directory does not exist")
        return False
    
    # Test 2: List directory contents
    debug_print("Listing scans directory contents...")
    try:
        dir_contents = os.listdir(scans_dir)
        debug_print(f"Directory contents: {dir_contents}")
    except Exception as e:
        debug_print(f"Error listing directory: {e}")
        return False
    
    # Test 3: Check each subdirectory
    for target_dir in dir_contents:
        target_path = os.path.join(scans_dir, target_dir)
        debug_print(f"Checking: {target_dir} -> {target_path}")
        
        if target_dir.startswith('.') or not os.path.isdir(target_path):
            debug_print(f"Skipping {target_dir} (hidden or not a directory)")
            continue
        
        debug_print(f"Scanning target directory: {target_dir}")
        
        try:
            file_contents = os.listdir(target_path)
            debug_print(f"Files in {target_dir}: {file_contents}")
            
            for filename in file_contents:
                if filename.endswith('.txt'):
                    file_path = os.path.join(target_path, filename)
                    debug_print(f"Found txt file: {file_path}")
                    
                    # Test reading the file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        debug_print(f"Successfully read file: {file_path} ({len(content)} characters)")
                    except Exception as e:
                        debug_print(f"Error reading file {file_path}: {e}")
                else:
                    debug_print(f"Skipping non-txt file: {filename}")
        except Exception as e:
            debug_print(f"Error listing directory {target_path}: {e}")
    
    # Test 4: Try to import and initialize RAG
    debug_print("Testing RAG import...")
    try:
        from lib.RAG import ScanRAG
        debug_print("Successfully imported ScanRAG")
    except Exception as e:
        debug_print(f"Error importing ScanRAG: {e}")
        return False
    
    # Test 5: Initialize RAG
    debug_print("Initializing RAG...")
    try:
        rag = ScanRAG()
        debug_print(f"RAG initialized. Documents: {len(rag.documents)}")
        return True
    except Exception as e:
        debug_print(f"Error initializing RAG: {e}")
        return False

if __name__ == "__main__":
    success = test_rag_step_by_step()
    if success:
        print("✅ RAG debug test completed successfully")
    else:
        print("❌ RAG debug test failed") 