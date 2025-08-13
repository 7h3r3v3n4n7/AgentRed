import os
import requests
import shutil
from typing import Dict, Optional, List
from pathlib import Path
import heapq
import aiohttp
import asyncio
from lib.config import Config
from lib.logging_utils import debug_print

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'

class WordlistManager:
    """Manages wordlists for various security tools"""
    
    def __init__(self, wordlists_dir: str = "wordlists", config: Config = None):
        self.config = config or Config()
        self.wordlists_dir = wordlists_dir
        self.wordlist_urls = {
            'web': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
                'filename': 'web_common.txt',
                'description': 'Common web paths and files'
            },
            'passwords': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
                'filename': 'passwords_common.txt',
                'description': 'Common passwords (top 1M)'
            },
            'usernames': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt',
                'filename': 'usernames_common.txt',
                'description': 'Common usernames'
            },
            'subdomains': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
                'filename': 'subdomains_common.txt',
                'description': 'Common subdomains'
            },
            'api': {
                'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt',
                'filename': 'api_endpoints.txt',
                'description': 'API endpoints'
            }
        }
        self.max_wordlists_mb = self.config.WORDLISTS_MAX_MB
        self._warned_this_session = False
        # Create wordlists directory if it doesn't exist
        os.makedirs(self.wordlists_dir, exist_ok=True)
        
        debug_print("WordlistManager initialized")
    
    def _get_total_wordlists_size(self) -> int:
        """Return total size of all wordlists in bytes"""
        total = 0
        for fname in os.listdir(self.wordlists_dir):
            fpath = os.path.join(self.wordlists_dir, fname)
            if os.path.isfile(fpath):
                total += os.path.getsize(fpath)
        return total

    def _get_wordlists_info(self):
        """Return list of (size, mtime, path) for all wordlists"""
        info = []
        for fname in os.listdir(self.wordlists_dir):
            fpath = os.path.join(self.wordlists_dir, fname)
            if os.path.isfile(fpath):
                stat = os.stat(fpath)
                info.append((stat.st_size, stat.st_mtime, fpath))
        return info

    def _maybe_warn_and_prompt_cleanup(self):
        total_mb = self._get_total_wordlists_size() / (1024*1024)
        if total_mb > self.max_wordlists_mb and not self._warned_this_session:
            print(f"\n⚠️  WARNING: Total wordlist size is {total_mb:.1f} MB (limit: {self.max_wordlists_mb} MB)")
            info = sorted(self._get_wordlists_info(), reverse=True)
            print("Largest wordlists:")
            for size, mtime, path in info[:5]:
                print(f"  {os.path.basename(path)} - {size/(1024*1024):.1f} MB")
            resp = input("Do you want to clean up old wordlists now? (y/N): ").strip().lower()
            if resp == 'y':
                # Delete oldest files until under limit
                info_by_age = sorted(self._get_wordlists_info(), key=lambda x: x[1])
                cur_total = total_mb
                deleted = []
                for size, mtime, path in info_by_age:
                    if cur_total <= self.max_wordlists_mb:
                        break
                    try:
                        os.remove(path)
                        cur_total -= size/(1024*1024)
                        deleted.append(path)
                        print(f"Deleted {os.path.basename(path)}")
                    except Exception as e:
                        print(f"Failed to delete {path}: {e}")
                print(f"Cleanup complete. Total wordlist size now {cur_total:.1f} MB.")
            else:
                print("No cleanup performed. You may encounter this warning again.")
                self._warned_this_session = True

    def _download_wordlist(self, url: str, filename: str) -> bool:
        """Download a wordlist from URL"""
        self._maybe_warn_and_prompt_cleanup()
        try:
            debug_print(f"Downloading wordlist from {url}")
            
            # Download with progress indicator
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            filepath = os.path.join(self.wordlists_dir, filename)
            total_size = int(response.headers.get('content-length', 0))
            
            with open(filepath, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Show progress for large files
                        if total_size > 0 and DEBUG:
                            progress = (downloaded / total_size) * 100
                            print(f"\rDownloading {filename}: {progress:.1f}%", end='', flush=True)
            
            if DEBUG and total_size > 0:
                print()  # New line after progress
            
            debug_print(f"Successfully downloaded {filename}")
            return True
            
        except Exception as e:
            debug_print(f"Error downloading wordlist from {url}: {e}")
            return False
    
    async def async_download_wordlist(self, url: str, filename: str) -> bool:
        """Asynchronously download a wordlist from URL with resume support"""
        self._maybe_warn_and_prompt_cleanup()
        filepath = os.path.join(self.wordlists_dir, filename)
        partfile = filepath + ".part"
        resume_byte_pos = 0
        if os.path.exists(partfile):
            resume_byte_pos = os.path.getsize(partfile)
        headers = {}
        if resume_byte_pos > 0:
            headers['Range'] = f'bytes={resume_byte_pos}-'
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=1200)) as resp:
                    if resp.status not in (200, 206):
                        debug_print(f"Failed to download {url}: HTTP {resp.status}")
                        return False
                    total_size = int(resp.headers.get('Content-Range', '').split('/')[-1] or resp.headers.get('Content-Length', 0))
                    mode = 'ab' if resume_byte_pos > 0 else 'wb'
                    downloaded = resume_byte_pos
                    chunk_size = 8192
                    with open(partfile, mode) as f:
                        async for chunk in resp.content.iter_chunked(chunk_size):
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)
                                if total_size > 0 and DEBUG:
                                    progress = (downloaded / total_size) * 100
                                    print(f"\rDownloading {filename}: {progress:.1f}%", end='', flush=True)
                    if DEBUG and total_size > 0:
                        print()
            # Rename .part to final filename
            os.rename(partfile, filepath)
            debug_print(f"Successfully downloaded {filename}")
            return True
        except Exception as e:
            debug_print(f"Error downloading wordlist from {url}: {e}")
            return False
    
    def _check_local_wordlists(self) -> Dict[str, Optional[str]]:
        """Check for existing wordlists in common locations"""
        wordlist_locations = {
            'web': [
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
            ],
            'passwords': [
                '/usr/share/wordlists/rockyou.txt',
                '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
                '/usr/share/wordlists/rockyou.txt.gz'
            ],
            'usernames': [
                '/usr/share/seclists/Usernames/Names/names.txt',
                '/usr/share/seclists/Usernames/top-usernames-shortlist.txt'
            ],
            'subdomains': [
                '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
                '/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt'
            ]
        }
        
        available_wordlists = {}
        
        for wordlist_type, locations in wordlist_locations.items():
            for location in locations:
                if os.path.exists(location):
                    available_wordlists[wordlist_type] = location
                    debug_print(f"Found {wordlist_type} wordlist: {location}")
                    break
        
        return available_wordlists
    
    def _check_downloaded_wordlists(self) -> Dict[str, Optional[str]]:
        """Check for wordlists in the local wordlists directory"""
        available_wordlists = {}
        
        for wordlist_type, info in self.wordlist_urls.items():
            filepath = os.path.join(self.wordlists_dir, info['filename'])
            if os.path.exists(filepath):
                available_wordlists[wordlist_type] = filepath
                debug_print(f"Found downloaded {wordlist_type} wordlist: {filepath}")
        
        return available_wordlists
    
    def get_available_wordlists(self) -> Dict[str, Optional[str]]:
        """Get all available wordlists (local + downloaded)"""
        local_wordlists = self._check_local_wordlists()
        downloaded_wordlists = self._check_downloaded_wordlists()
        
        # Combine both, with local wordlists taking precedence
        all_wordlists = {**downloaded_wordlists, **local_wordlists}
        
        debug_print(f"Available wordlists: {list(all_wordlists.keys())}")
        return all_wordlists
    
    def ensure_wordlist(self, wordlist_type: str) -> Optional[str]:
        """Ensure a wordlist is available, downloading if necessary"""
        available_wordlists = self.get_available_wordlists()
        
        # If wordlist is already available, return it
        if wordlist_type in available_wordlists:
            return available_wordlists[wordlist_type]
        
        # If not available, try to download it
        if wordlist_type in self.wordlist_urls:
            info = self.wordlist_urls[wordlist_type]
            print(f"Downloading {info['description']}...")
            
            if self._download_wordlist(info['url'], info['filename']):
                filepath = os.path.join(self.wordlists_dir, info['filename'])
                if os.path.exists(filepath):
                    print(f"✅ Downloaded {info['description']}")
                    return filepath
                else:
                    print(f"❌ Failed to download {info['description']}")
            else:
                print(f"❌ Failed to download {info['description']}")
        
        return None
    
    def get_best_wordlist(self, wordlist_type: str) -> Optional[str]:
        """Get the best available wordlist for a given type"""
        return self.ensure_wordlist(wordlist_type)
    
    def list_wordlists(self) -> Dict[str, Dict[str, str]]:
        """List all available wordlists with their details"""
        available_wordlists = self.get_available_wordlists()
        wordlist_details = {}
        
        for wordlist_type, filepath in available_wordlists.items():
            if os.path.exists(filepath):
                size = os.path.getsize(filepath)
                wordlist_details[wordlist_type] = {
                    'path': filepath,
                    'size': size,
                    'size_mb': f"{size / (1024*1024):.1f} MB",
                    'lines': self._count_lines(filepath)
                }
        
        return wordlist_details
    
    def _count_lines(self, filepath: str) -> int:
        """Count lines in a file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    
    def download_all_wordlists(self) -> Dict[str, bool]:
        """Download all wordlists"""
        results = {}
        
        print("Downloading wordlists...")
        for wordlist_type, info in self.wordlist_urls.items():
            print(f"Downloading {info['description']}...")
            success = self._download_wordlist(info['url'], info['filename'])
            results[wordlist_type] = success
            
            if success:
                print(f"✅ Downloaded {info['description']}")
            else:
                print(f"❌ Failed to download {info['description']}")
        
        return results
    
    def cleanup_wordlists(self):
        """Remove downloaded wordlists"""
        for wordlist_type, info in self.wordlist_urls.items():
            filepath = os.path.join(self.wordlists_dir, info['filename'])
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    debug_print(f"Removed {filepath}")
                except Exception as e:
                    debug_print(f"Error removing {filepath}: {e}")
    
    def get_wordlist_info(self, wordlist_type: str) -> Optional[Dict[str, str]]:
        """Get information about a specific wordlist"""
        wordlist_path = self.get_best_wordlist(wordlist_type)
        
        if wordlist_path and os.path.exists(wordlist_path):
            size = os.path.getsize(wordlist_path)
            lines = self._count_lines(wordlist_path)
            
            return {
                'path': wordlist_path,
                'size': f"{size / (1024*1024):.1f} MB",
                'lines': f"{lines:,}",
                'type': wordlist_type
            }
        
        return None 
