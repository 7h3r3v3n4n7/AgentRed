#!/usr/bin/env python3
"""
Test script for RAG functionality
"""

import os
import sys
import datetime
from pathlib import Path

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from lib.RAG import ScanRAG, ScanDocument
from lib.Tools import Tools

def create_sample_scan_files():
    """Create sample scan files for testing"""
    scans_dir = "scans"
    os.makedirs(scans_dir, exist_ok=True)
    
    # Create a sample target directory
    target_dir = os.path.join(scans_dir, "example.com_20241201_120000")
    os.makedirs(target_dir, exist_ok=True)
    
    # Sample nmap scan result
    nmap_content = """Command: nmap
Target: example.com
Timestamp: 2024-12-01T12:00:00
Success: True
==================================================

Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.089s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx
443/tcp open  https    nginx
| ssl-cert: Subject: commonName=example.com
| SSL/TLS: TLSv1.2, TLSv1.3
|_http-server-header: nginx
|_http-title: Example Domain

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds
"""
    
    # Sample nikto scan result
    nikto_content = """Command: nikto
Target: example.com
Timestamp: 2024-12-01T12:05:00
Success: True
==================================================

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    example.com
+ Target Port:        80
+ Start Time:         2024-12-01 12:05:00 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx
+ Cookie PHPSESSID created without the httponly flag
+ /admin/: Admin login page/section found.
+ /robots.txt: Robots.txt file found.
+ /sitemap.xml: Sitemap file found.
---------------------------------------------------------------------------
+ 1 host(s) tested
"""
    
    # Sample gobuster scan result
    gobuster_content = """Command: gobuster
Target: example.com
Timestamp: 2024-12-01T12:10:00
Success: True
==================================================

Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
==================================================
[+] Url:            http://example.com
[+] Method:         GET
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,403
==================================================
/admin/              (Status: 403) [Size: 162]
/robots.txt          (Status: 200) [Size: 23]
/sitemap.xml         (Status: 200) [Size: 45]
/wp-admin/           (Status: 403) [Size: 162]
==================================================
"""
    
    # Write sample files
    with open(os.path.join(target_dir, "nmap.txt"), 'w') as f:
        f.write(nmap_content)
    
    with open(os.path.join(target_dir, "nikto.txt"), 'w') as f:
        f.write(nikto_content)
    
    with open(os.path.join(target_dir, "gobuster.txt"), 'w') as f:
        f.write(gobuster_content)
    
    print(f"Created sample scan files in {target_dir}")
    return target_dir

def test_rag_functionality():
    """Test the RAG functionality"""
    print("🧪 Testing RAG functionality...")
    
    # Create sample data
    sample_dir = create_sample_scan_files()
    
    # Initialize RAG
    try:
        rag = ScanRAG("scans")
        print("✅ RAG system initialized")
        
        # Test search functionality
        print("\n🔍 Testing search functionality...")
        
        # Search for web-related findings
        results = rag.search("web server nginx", top_k=3)
        print(f"Found {len(results)} results for 'web server nginx'")
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result.document.tool} - Score: {result.score:.3f}")
            print(f"     Snippet: {result.snippet}")
        
        # Search for admin interfaces
        results = rag.search("admin login", top_k=3)
        print(f"\nFound {len(results)} results for 'admin login'")
        for i, result in enumerate(results, 1):
            print(f"  {i}. {result.document.tool} - Score: {result.score:.3f}")
            print(f"     Snippet: {result.snippet}")
        
        # Test summary
        print("\n📊 Testing summary functionality...")
        summary = rag.get_summary()
        print(f"Total documents: {summary['total_documents']}")
        print(f"Targets: {summary['targets']}")
        print(f"Tools: {summary['tools']}")
        
        # Test target-specific search
        print("\n🎯 Testing target-specific search...")
        results = rag.search("ports services", target_filter="example.com")
        print(f"Found {len(results)} results for 'ports services' on example.com")
        
    except Exception as e:
        print(f"❌ Error testing RAG: {e}")
        return False
    
    return True

def test_tools_integration():
    """Test RAG integration with Tools class"""
    print("\n🔧 Testing Tools integration...")
    
    try:
        tools = Tools()
        
        if tools.is_rag_available():
            print("✅ RAG is available in Tools")
            
            # Test search through Tools
            results = tools.search_scan_results("nginx web server", top_k=3)
            print(f"Found {len(results)} results through Tools.search_scan_results()")
            
            # Test summary through Tools
            summary = tools.get_scan_summary()
            print(f"Summary through Tools: {summary['total_documents']} documents")
            
        else:
            print("❌ RAG not available in Tools")
            return False
            
    except Exception as e:
        print(f"❌ Error testing Tools integration: {e}")
        return False
    
    return True

def main():
    """Main test function"""
    print("🚀 Starting RAG functionality tests...")
    
    # Test basic RAG functionality
    if not test_rag_functionality():
        print("❌ Basic RAG test failed")
        return
    
    # Test Tools integration
    if not test_tools_integration():
        print("❌ Tools integration test failed")
        return
    
    print("\n✅ All tests passed!")
    print("\nTo use RAG in the main application:")
    print("1. Install dependencies: pip install sentence-transformers faiss-cpu numpy")
    print("2. Run the main application: python main.py")
    print("3. The model will automatically reference previous scan results")

if __name__ == "__main__":
    main() 