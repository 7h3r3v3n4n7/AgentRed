import os
import json
import re
import hashlib
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import pickle
from pathlib import Path

# For embeddings and vector search
try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    import faiss
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    print("Warning: RAG features require additional packages. Install with: pip install sentence-transformers faiss-cpu numpy")

# Load environment variables
DEBUG = os.getenv('DEBUG', '0') == '1'

def debug_print(*args, **kwargs):
    """Print debug messages only if DEBUG is enabled"""
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

@dataclass
class ScanDocument:
    """Represents a scan result document"""
    id: str
    target: str
    tool: str
    timestamp: str
    content: str
    file_path: str
    metadata: Dict[str, Any]

@dataclass
class SearchResult:
    """Represents a search result"""
    document: ScanDocument
    score: float
    snippet: str

class ScanRAG:
    """RAG system for scan results"""
    
    def __init__(self, scans_dir: str = "scans", model_name: str = "all-MiniLM-L6-v2"):
        self.scans_dir = scans_dir
        self.model_name = model_name
        self.index_dir = os.path.join(scans_dir, ".rag_index")
        self.documents: List[ScanDocument] = []
        self.embeddings = None
        self.index = None
        self.model = None
        
        # Create index directory
        os.makedirs(self.index_dir, exist_ok=True)
        
        # Initialize if RAG is available
        if RAG_AVAILABLE:
            self._initialize_model()
            self._load_or_create_index()
        else:
            debug_print("RAG features not available - using simple text search")
    
    def _initialize_model(self):
        """Initialize the sentence transformer model"""
        try:
            debug_print(f"Loading sentence transformer model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name)
            debug_print("Model loaded successfully")
        except Exception as e:
            debug_print(f"Error loading model: {e}")
            RAG_AVAILABLE = False
    
    def _load_or_create_index(self):
        """Load existing index or create new one"""
        index_file = os.path.join(self.index_dir, "faiss_index.bin")
        docs_file = os.path.join(self.index_dir, "documents.pkl")
        
        if os.path.exists(index_file) and os.path.exists(docs_file):
            try:
                debug_print("Loading existing RAG index...")
                self.index = faiss.read_index(index_file)
                with open(docs_file, 'rb') as f:
                    self.documents = pickle.load(f)
                debug_print(f"Loaded {len(self.documents)} documents from index")
            except Exception as e:
                debug_print(f"Error loading index: {e}")
                self._create_new_index()
        else:
            self._create_new_index()
    
    def _create_new_index(self):
        """Create a new index from scan files"""
        debug_print("Creating new RAG index...")
        self.documents = []
        self._scan_and_index_files()
        self._build_index()
        self._save_index()
    
    def _scan_and_index_files(self):
        """Scan all scan result files and create documents"""
        debug_print(f"Starting to scan directory: {self.scans_dir}")
        if not os.path.exists(self.scans_dir):
            debug_print(f"Scans directory does not exist: {self.scans_dir}")
            return
        
        debug_print(f"Scans directory exists, listing contents...")
        dir_contents = os.listdir(self.scans_dir)
        debug_print(f"Directory contents: {dir_contents}")
        
        for target_dir in dir_contents:
            target_path = os.path.join(self.scans_dir, target_dir)
            debug_print(f"Checking: {target_dir} -> {target_path}")
            
            # Skip hidden directories and the index directory
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
                        debug_print(f"Processing file: {file_path}")
                        self._process_scan_file(file_path, target_dir)
                    else:
                        debug_print(f"Skipping non-txt file: {filename}")
            except Exception as e:
                debug_print(f"Error listing directory {target_path}: {e}")
        
        debug_print(f"Scan complete. Total documents: {len(self.documents)}")
    
    def _process_scan_file(self, file_path: str, target_dir: str):
        """Process a single scan result file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse file metadata from content
            metadata = self._parse_scan_metadata(content)
            
            # Extract tool name from filename
            tool_name = os.path.splitext(os.path.basename(file_path))[0]
            
            # Create document ID
            doc_id = hashlib.md5(f"{file_path}:{os.path.getmtime(file_path)}".encode()).hexdigest()
            
            # Create document
            document = ScanDocument(
                id=doc_id,
                target=metadata.get('target', target_dir),
                tool=tool_name,
                timestamp=metadata.get('timestamp', ''),
                content=content,
                file_path=file_path,
                metadata=metadata
            )
            
            self.documents.append(document)
            debug_print(f"Indexed document: {tool_name} for {target_dir}")
            
        except Exception as e:
            debug_print(f"Error processing file {file_path}: {e}")
    
    def _parse_scan_metadata(self, content: str) -> Dict[str, Any]:
        """Parse metadata from scan file content"""
        metadata = {}
        
        # Extract target
        target_match = re.search(r'Target:\s*(.+)', content)
        if target_match:
            metadata['target'] = target_match.group(1).strip()
        
        # Extract timestamp
        timestamp_match = re.search(r'Timestamp:\s*(.+)', content)
        if timestamp_match:
            metadata['timestamp'] = timestamp_match.group(1).strip()
        
        # Extract success status
        success_match = re.search(r'Success:\s*(.+)', content)
        if success_match:
            metadata['success'] = success_match.group(1).strip().lower() == 'true'
        
        # Extract error if present
        error_match = re.search(r'Error:\s*(.+)', content)
        if error_match:
            metadata['error'] = error_match.group(1).strip()
        
        return metadata
    
    def _build_index(self):
        """Build FAISS index from documents"""
        if not self.documents or not RAG_AVAILABLE:
            return
        
        debug_print("Building FAISS index...")
        
        # Create embeddings for all documents
        texts = [doc.content for doc in self.documents]
        embeddings = self.model.encode(texts, show_progress_bar=True)
        
        # Normalize embeddings
        faiss.normalize_L2(embeddings)
        
        # Create FAISS index
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dimension)  # Inner product for cosine similarity
        self.index.add(embeddings.astype('float32'))
        
        self.embeddings = embeddings
        debug_print(f"Built index with {len(self.documents)} documents")
    
    def _save_index(self):
        """Save the index and documents to disk"""
        if not RAG_AVAILABLE or not self.index:
            return
        
        try:
            # Save FAISS index
            index_file = os.path.join(self.index_dir, "faiss_index.bin")
            faiss.write_index(self.index, index_file)
            
            # Save documents
            docs_file = os.path.join(self.index_dir, "documents.pkl")
            with open(docs_file, 'wb') as f:
                pickle.dump(self.documents, f)
            
            debug_print("Index saved successfully")
        except Exception as e:
            debug_print(f"Error saving index: {e}")
    
    def search(self, query: str, top_k: int = 5, target_filter: Optional[str] = None) -> List[SearchResult]:
        """Search for relevant scan results"""
        if not self.documents:
            return []
        
        if RAG_AVAILABLE and self.model and self.index:
            return self._semantic_search(query, top_k, target_filter)
        else:
            return self._text_search(query, top_k, target_filter)
    
    def _semantic_search(self, query: str, top_k: int, target_filter: Optional[str]) -> List[SearchResult]:
        """Perform semantic search using embeddings"""
        try:
            # Encode query
            query_embedding = self.model.encode([query])
            faiss.normalize_L2(query_embedding)
            
            # Search index
            scores, indices = self.index.search(query_embedding.astype('float32'), min(top_k * 2, len(self.documents)))
            
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx == -1:  # FAISS returns -1 for empty slots
                    continue
                
                doc = self.documents[idx]
                
                # Apply target filter if specified
                if target_filter and target_filter.lower() not in doc.target.lower():
                    continue
                
                # Create snippet
                snippet = self._create_snippet(query, doc.content)
                
                results.append(SearchResult(
                    document=doc,
                    score=float(score),
                    snippet=snippet
                ))
                
                if len(results) >= top_k:
                    break
            
            return results
            
        except Exception as e:
            debug_print(f"Error in semantic search: {e}")
            return self._text_search(query, top_k, target_filter)
    
    def _text_search(self, query: str, top_k: int, target_filter: Optional[str]) -> List[SearchResult]:
        """Perform simple text search"""
        query_terms = query.lower().split()
        results = []
        
        for doc in self.documents:
            # Apply target filter if specified
            if target_filter and target_filter.lower() not in doc.target.lower():
                continue
            
            # Calculate simple relevance score
            content_lower = doc.content.lower()
            score = sum(1 for term in query_terms if term in content_lower)
            
            # Bonus for exact matches
            if query.lower() in content_lower:
                score += 2
            
            if score > 0:
                snippet = self._create_snippet(query, doc.content)
                results.append(SearchResult(
                    document=doc,
                    score=score,
                    snippet=snippet
                ))
        
        # Sort by score and return top_k
        results.sort(key=lambda x: x.score, reverse=True)
        return results[:top_k]
    
    def _create_snippet(self, query: str, content: str, max_length: int = 200) -> str:
        """Create a snippet highlighting the query terms"""
        # Find the best matching section
        query_terms = query.lower().split()
        lines = content.split('\n')
        
        best_line = ""
        best_score = 0
        
        for line in lines:
            line_lower = line.lower()
            score = sum(1 for term in query_terms if term in line_lower)
            if score > best_score:
                best_score = score
                best_line = line
        
        if best_line:
            # Truncate if too long
            if len(best_line) > max_length:
                best_line = best_line[:max_length] + "..."
            return best_line
        
        # Fallback to first part of content
        return content[:max_length] + "..." if len(content) > max_length else content
    
    def get_targets(self) -> List[str]:
        """Get list of all targets in the index"""
        targets = set()
        for doc in self.documents:
            targets.add(doc.target)
        return sorted(list(targets))
    
    def get_tools(self) -> List[str]:
        """Get list of all tools used in the index"""
        tools = set()
        for doc in self.documents:
            tools.add(doc.tool)
        return sorted(list(tools))
    
    def get_documents_by_target(self, target: str) -> List[ScanDocument]:
        """Get all documents for a specific target"""
        return [doc for doc in self.documents if target.lower() in doc.target.lower()]
    
    def get_documents_by_tool(self, tool: str) -> List[ScanDocument]:
        """Get all documents for a specific tool"""
        return [doc for doc in self.documents if doc.tool.lower() == tool.lower()]
    
    def refresh_index(self):
        """Refresh the index by re-scanning all files"""
        debug_print("Refreshing RAG index...")
        self.documents = []
        self._scan_and_index_files()
        if RAG_AVAILABLE:
            self._build_index()
            self._save_index()
        debug_print(f"Index refreshed with {len(self.documents)} documents")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the indexed data"""
        if not self.documents:
            return {"message": "No documents indexed"}
        
        targets = self.get_targets()
        tools = self.get_tools()
        
        # Count documents by tool
        tool_counts = {}
        for doc in self.documents:
            tool_counts[doc.tool] = tool_counts.get(doc.tool, 0) + 1
        
        # Count documents by target
        target_counts = {}
        for doc in self.documents:
            target_counts[doc.target] = target_counts.get(doc.target, 0) + 1
        
        return {
            "total_documents": len(self.documents),
            "targets": targets,
            "tools": tools,
            "tool_counts": tool_counts,
            "target_counts": target_counts,
            "index_type": "semantic" if RAG_AVAILABLE else "text"
        } 