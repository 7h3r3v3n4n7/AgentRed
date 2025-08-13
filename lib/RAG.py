import os
import json
import re
import hashlib
from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import pickle
from pathlib import Path
from collections import defaultdict, Counter
import networkx as nx
import heapq
from lib.config import Config
from lib.logging_utils import debug_print

# For embeddings and vector search
try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
    # Try to import faiss, but don't fail if it's not available
    try:
        import faiss
        FAISS_AVAILABLE = True
    except ImportError:
        FAISS_AVAILABLE = False
        debug_print("FAISS not available, will use text search only")
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    FAISS_AVAILABLE = False
    print("Warning: RAG features require additional packages. Install with: pip install sentence-transformers faiss-cpu numpy")

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

@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding"""
    id: str
    target: str
    tool: str
    timestamp: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    cve_ids: List[str]
    cvss_score: Optional[float]
    remediation: str
    confidence: float

@dataclass
class CorrelationResult:
    """Represents correlation analysis results"""
    primary_finding: VulnerabilityFinding
    correlated_findings: List[VulnerabilityFinding]
    correlation_strength: float
    correlation_type: str
    attack_path: List[str]

@dataclass
class TemporalAnalysis:
    """Represents temporal analysis results"""
    target: str
    time_period: str
    scan_frequency: int
    vulnerability_trends: Dict[str, int]
    tool_usage_trends: Dict[str, int]
    risk_score_trend: List[float]

@dataclass
class CorrelationResult:
    """Represents correlation analysis results"""
    primary_finding: VulnerabilityFinding
    correlated_findings: List[VulnerabilityFinding]
    correlation_strength: float
    correlation_type: str
    attack_path: List[str]

class EnhancedScanRAG:
    """Enhanced RAG system for scan results with advanced analytics"""
    
    def __init__(self, scans_dir: str = "scans", model_name: str = "all-MiniLM-L6-v2", config: Config = None):
        self.config = config or Config()
        self.scans_dir = scans_dir
        self.model_name = model_name
        self.index_dir = os.path.join(scans_dir, ".rag_index")
        os.makedirs(self.index_dir, exist_ok=True)
        self.documents = []
        self.index = None
        self.max_docs = self.config.RAG_MAX_DOCS
        self.max_mb = self.config.RAG_MAX_MB
        self._warned_rag_session = False
        self.embeddings = None
        self.model = None
        
        # Enhanced features
        self.vulnerability_findings: List[VulnerabilityFinding] = []
        self.knowledge_graph = nx.DiGraph()
        self.temporal_data = defaultdict(list)
        self.correlation_cache = {}
        self.insight_cache = {}
        
        self._initialize_model()
        self._load_or_create_index()
        self._maybe_warn_and_prompt_rag_cleanup()
        self._build_knowledge_graph()
        self._extract_vulnerabilities()
        self._analyze_temporal_patterns()
    
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
        docs_file = os.path.join(self.index_dir, "documents.pkl")
        
        if FAISS_AVAILABLE:
            index_file = os.path.join(self.index_dir, "faiss_index.bin")
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
        else:
            # Without FAISS, just load documents
            if os.path.exists(docs_file):
                try:
                    debug_print("Loading existing documents...")
                    with open(docs_file, 'rb') as f:
                        self.documents = pickle.load(f)
                    debug_print(f"Loaded {len(self.documents)} documents")
                except Exception as e:
                    debug_print(f"Error loading documents: {e}")
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
        """Build index from documents"""
        if not self.documents or not RAG_AVAILABLE:
            return
        
        debug_print("Building index...")
        
        if FAISS_AVAILABLE and self.model:
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
            debug_print(f"Built FAISS index with {len(self.documents)} documents")
        else:
            # Store embeddings without FAISS
            if self.model:
                texts = [doc.content for doc in self.documents]
                self.embeddings = self.model.encode(texts, show_progress_bar=True)
                debug_print(f"Built embeddings for {len(self.documents)} documents (no FAISS)")
            else:
                debug_print("No model available, using text search only")
    
    def _save_index(self):
        """Save the index and documents to disk"""
        if not RAG_AVAILABLE:
            return
        
        try:
            # Save documents
            docs_file = os.path.join(self.index_dir, "documents.pkl")
            with open(docs_file, 'wb') as f:
                pickle.dump(self.documents, f)
            
            # Save FAISS index if available
            if FAISS_AVAILABLE and self.index:
                index_file = os.path.join(self.index_dir, "faiss_index.bin")
                faiss.write_index(self.index, index_file)
            
            debug_print("Index saved successfully")
        except Exception as e:
            debug_print(f"Error saving index: {e}")
    
    def _extract_vulnerabilities(self):
        """Extract vulnerability findings from scan documents"""
        debug_print("Extracting vulnerability findings...")
        
        vulnerability_patterns = {
            'sql_injection': [r'sql.*injection', r'sqli', r'blind.*sql'],
            'xss': [r'xss', r'cross.*site.*scripting', r'<script>'],
            'rce': [r'remote.*code.*execution', r'rce', r'command.*injection'],
            'lfi': [r'local.*file.*inclusion', r'lfi', r'path.*traversal'],
            'ssrf': [r'server.*side.*request.*forgery', r'ssrf'],
            'xxe': [r'xml.*external.*entity', r'xxe'],
            'open_redirect': [r'open.*redirect', r'redirect.*vulnerability'],
            'weak_auth': [r'weak.*password', r'default.*credentials', r'admin.*admin'],
            'ssl_issues': [r'ssl.*vulnerability', r'tls.*weak', r'certificate.*error'],
            'open_ports': [r'port.*\d+.*open', r'open.*port'],
            'default_services': [r'default.*service', r'default.*configuration'],
            'information_disclosure': [r'information.*disclosure', r'error.*message', r'debug.*info']
        }
        
        for doc in self.documents:
            content_lower = doc.content.lower()
            
            for vuln_type, patterns in vulnerability_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content_lower, re.IGNORECASE)
                    for match in matches:
                        # Extract context around the match
                        start = max(0, match.start() - 100)
                        end = min(len(doc.content), match.end() + 100)
                        context = doc.content[start:end]
                        
                        # Determine severity based on vulnerability type and context
                        severity = self._determine_severity(vuln_type, context)
                        
                        # Extract CVE IDs if present
                        cve_ids = re.findall(r'CVE-\d{4}-\d+', context, re.IGNORECASE)
                        
                        # Calculate confidence based on context quality
                        confidence = self._calculate_confidence(context, vuln_type)
                        
                        finding = VulnerabilityFinding(
                            id=f"{doc.id}_{vuln_type}_{hash(context) % 10000}",
                            target=doc.target,
                            tool=doc.tool,
                            timestamp=doc.timestamp,
                            vulnerability_type=vuln_type,
                            severity=severity,
                            description=f"{vuln_type.replace('_', ' ').title()} detected",
                            evidence=context,
                            cve_ids=cve_ids,
                            cvss_score=self._estimate_cvss_score(severity, vuln_type),
                            remediation=self._generate_remediation(vuln_type),
                            confidence=confidence
                        )
                        
                        self.vulnerability_findings.append(finding)
        
        debug_print(f"Extracted {len(self.vulnerability_findings)} vulnerability findings")
    
    def _determine_severity(self, vuln_type: str, context: str) -> str:
        """Determine severity based on vulnerability type and context"""
        high_severity = ['rce', 'sql_injection', 'xxe', 'ssrf']
        medium_severity = ['xss', 'lfi', 'open_redirect', 'weak_auth']
        low_severity = ['information_disclosure', 'open_ports', 'default_services']
        
        if vuln_type in high_severity:
            return 'high'
        elif vuln_type in medium_severity:
            return 'medium'
        elif vuln_type in low_severity:
            return 'low'
        else:
            return 'medium'
    
    def _calculate_confidence(self, context: str, vuln_type: str) -> float:
        """Calculate confidence score for vulnerability finding"""
        # Base confidence
        confidence = 0.5
        
        # Increase confidence based on context quality
        if len(context) > 50:
            confidence += 0.2
        
        # Increase confidence for specific patterns
        if re.search(r'vulnerability|vuln|exploit', context, re.IGNORECASE):
            confidence += 0.2
        
        # Increase confidence for high-severity vulnerabilities
        if vuln_type in ['rce', 'sql_injection', 'xxe']:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _estimate_cvss_score(self, severity: str, vuln_type: str) -> float:
        """Estimate CVSS score based on severity and vulnerability type"""
        base_scores = {
            'high': 8.0,
            'medium': 5.0,
            'low': 3.0
        }
        
        base_score = base_scores.get(severity, 5.0)
        
        # Adjust based on vulnerability type
        if vuln_type in ['rce', 'sql_injection']:
            base_score += 1.0
        elif vuln_type in ['xss', 'lfi']:
            base_score += 0.5
        
        return min(base_score, 10.0)
    
    def _generate_remediation(self, vuln_type: str) -> str:
        """Generate remediation advice for vulnerability type"""
        remediation_map = {
            'sql_injection': 'Use parameterized queries and input validation',
            'xss': 'Implement proper output encoding and CSP headers',
            'rce': 'Validate and sanitize all user inputs, use allowlists',
            'lfi': 'Use absolute paths and input validation',
            'ssrf': 'Validate URLs and implement allowlists for external requests',
            'xxe': 'Disable XML external entity processing',
            'open_redirect': 'Validate redirect URLs and use allowlists',
            'weak_auth': 'Implement strong password policies and MFA',
            'ssl_issues': 'Update SSL/TLS configuration and certificates',
            'open_ports': 'Close unnecessary ports and implement firewall rules',
            'default_services': 'Change default credentials and configurations',
            'information_disclosure': 'Remove debug information and error details'
        }
        
        return remediation_map.get(vuln_type, 'Review and fix the identified security issue')
    
    def _build_knowledge_graph(self):
        """Build a knowledge graph from scan data"""
        debug_print("Building knowledge graph...")
        
        # Add nodes for targets, tools, and vulnerabilities
        for doc in self.documents:
            self.knowledge_graph.add_node(doc.target, type='target')
            self.knowledge_graph.add_node(doc.tool, type='tool')
            self.knowledge_graph.add_edge(doc.tool, doc.target, relationship='scanned')
        
        # Add vulnerability nodes and relationships
        for finding in self.vulnerability_findings:
            vuln_node = f"{finding.vulnerability_type}_{finding.target}"
            self.knowledge_graph.add_node(vuln_node, type='vulnerability', severity=finding.severity)
            self.knowledge_graph.add_edge(finding.tool, vuln_node, relationship='detected')
            self.knowledge_graph.add_edge(vuln_node, finding.target, relationship='affects')
        
        debug_print(f"Knowledge graph built with {self.knowledge_graph.number_of_nodes()} nodes and {self.knowledge_graph.number_of_edges()} edges")
    
    def _analyze_temporal_patterns(self):
        """Analyze temporal patterns in scan data"""
        debug_print("Analyzing temporal patterns...")
        
        for doc in self.documents:
            try:
                timestamp = datetime.fromisoformat(doc.timestamp.replace('Z', '+00:00'))
                self.temporal_data[doc.target].append({
                    'timestamp': timestamp,
                    'tool': doc.tool,
                    'success': doc.metadata.get('success', True)
                })
            except:
                continue
        
        # Sort temporal data by timestamp
        for target in self.temporal_data:
            self.temporal_data[target].sort(key=lambda x: x['timestamp'])
    
    def search(self, query: str, top_k: int = 5, target_filter: Optional[str] = None) -> List[SearchResult]:
        """Search for relevant scan results"""
        if not self.documents:
            return []
        
        if RAG_AVAILABLE and self.model and FAISS_AVAILABLE and self.index:
            return self._semantic_search(query, top_k, target_filter)
        elif RAG_AVAILABLE and self.model and self.embeddings is not None:
            return self._embedding_search(query, top_k, target_filter)
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
    
    def _embedding_search(self, query: str, top_k: int, target_filter: Optional[str]) -> List[SearchResult]:
        """Perform search using embeddings without FAISS"""
        try:
            # Encode query
            query_embedding = self.model.encode([query])
            
            # Calculate cosine similarities manually
            similarities = []
            for i, doc_embedding in enumerate(self.embeddings):
                # Calculate cosine similarity
                dot_product = np.dot(query_embedding[0], doc_embedding)
                norm_query = np.linalg.norm(query_embedding[0])
                norm_doc = np.linalg.norm(doc_embedding)
                similarity = dot_product / (norm_query * norm_doc)
                similarities.append((similarity, i))
            
            # Sort by similarity
            similarities.sort(reverse=True)
            
            results = []
            for similarity, idx in similarities[:top_k * 2]:
                doc = self.documents[idx]
                
                # Apply target filter if specified
                if target_filter and target_filter.lower() not in doc.target.lower():
                    continue
                
                # Create snippet
                snippet = self._create_snippet(query, doc.content)
                
                results.append(SearchResult(
                    document=doc,
                    score=float(similarity),
                    snippet=snippet
                ))
                
                if len(results) >= top_k:
                    break
            
            return results
            
        except Exception as e:
            debug_print(f"Error in embedding search: {e}")
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
    
    # Enhanced RAG methods
    def get_vulnerability_correlations(self, target: str = None) -> List[CorrelationResult]:
        """Find correlated vulnerabilities"""
        if not self.vulnerability_findings:
            return []
        
        correlations = []
        target_findings = [f for f in self.vulnerability_findings if not target or f.target == target]
        
        for i, finding in enumerate(target_findings):
            correlated = []
            
            for other_finding in target_findings[i+1:]:
                # Check for correlations based on various factors
                correlation_strength = self._calculate_correlation_strength(finding, other_finding)
                
                if correlation_strength > 0.3:  # Threshold for correlation
                    correlated.append(other_finding)
            
            if correlated:
                correlations.append(CorrelationResult(
                    primary_finding=finding,
                    correlated_findings=correlated,
                    correlation_strength=max(c.correlation_strength for c in correlated) if correlated else 0,
                    correlation_type=self._determine_correlation_type(finding, correlated),
                    attack_path=self._generate_attack_path(finding, correlated)
                ))
        
        return correlations
    
    def _calculate_correlation_strength(self, finding1: VulnerabilityFinding, finding2: VulnerabilityFinding) -> float:
        """Calculate correlation strength between two findings"""
        strength = 0.0
        
        # Same vulnerability type
        if finding1.vulnerability_type == finding2.vulnerability_type:
            strength += 0.4
        
        # Same severity
        if finding1.severity == finding2.severity:
            strength += 0.2
        
        # Same tool
        if finding1.tool == finding2.tool:
            strength += 0.2
        
        # Temporal proximity (within 24 hours)
        try:
            time1 = datetime.fromisoformat(finding1.timestamp.replace('Z', '+00:00'))
            time2 = datetime.fromisoformat(finding2.timestamp.replace('Z', '+00:00'))
            if abs((time1 - time2).total_seconds()) < 86400:  # 24 hours
                strength += 0.2
        except:
            pass
        
        return min(strength, 1.0)
    
    def _determine_correlation_type(self, finding: VulnerabilityFinding, correlated: List[VulnerabilityFinding]) -> str:
        """Determine the type of correlation"""
        if len(correlated) == 0:
            return "none"
        
        # Check for attack chain patterns
        vuln_types = [f.vulnerability_type for f in correlated]
        all_types = [finding.vulnerability_type] + vuln_types
        
        if 'sql_injection' in all_types and 'xss' in all_types:
            return "attack_chain"
        elif 'weak_auth' in all_types and 'rce' in all_types:
            return "privilege_escalation"
        elif len(set(all_types)) > 3:
            return "multiple_vulnerabilities"
        else:
            return "similar_findings"
    
    def _generate_attack_path(self, finding: VulnerabilityFinding, correlated: List[VulnerabilityFinding]) -> List[str]:
        """Generate potential attack path"""
        path = [finding.vulnerability_type]
        
        # Add correlated vulnerabilities in logical order
        for corr in correlated:
            if corr.vulnerability_type not in path:
                path.append(corr.vulnerability_type)
        
        return path
    
    def get_temporal_analysis(self, target: str, days: int = 30) -> TemporalAnalysis:
        """Get temporal analysis for a target"""
        if target not in self.temporal_data:
            return None
        
        target_data = self.temporal_data[target]
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_data = [d for d in target_data if d['timestamp'] > cutoff_date]
        
        if not recent_data:
            return None
        
        # Calculate trends
        vulnerability_trends = Counter()
        tool_usage_trends = Counter()
        risk_scores = []
        
        for data in recent_data:
            tool_usage_trends[data['tool']] += 1
            
            # Find vulnerabilities for this timestamp
            for finding in self.vulnerability_findings:
                if finding.target == target:
                    try:
                        finding_time = datetime.fromisoformat(finding.timestamp.replace('Z', '+00:00'))
                        if abs((finding_time - data['timestamp']).total_seconds()) < 3600:  # Within 1 hour
                            vulnerability_trends[finding.vulnerability_type] += 1
                            risk_scores.append(finding.cvss_score or 5.0)
                    except:
                        continue
        
        return TemporalAnalysis(
            target=target,
            time_period=f"Last {days} days",
            scan_frequency=len(recent_data),
            vulnerability_trends=dict(vulnerability_trends),
            tool_usage_trends=dict(tool_usage_trends),
            risk_score_trend=risk_scores
        )
    
    def get_automated_insights(self, target: str = None) -> List[Dict[str, Any]]:
        """Generate automated insights from scan data"""
        insights = []
        
        # High-risk vulnerabilities
        high_risk_findings = [f for f in self.vulnerability_findings 
                            if f.severity == 'high' and (not target or f.target == target)]
        if high_risk_findings:
            insights.append({
                'type': 'high_risk_vulnerabilities',
                'title': f'High-Risk Vulnerabilities Detected',
                'description': f'Found {len(high_risk_findings)} high-risk vulnerabilities',
                'details': [f'{f.vulnerability_type} on {f.target}' for f in high_risk_findings[:5]],
                'priority': 'critical'
            })
        
        # Attack chains
        correlations = self.get_vulnerability_correlations(target)
        attack_chains = [c for c in correlations if c.correlation_type == 'attack_chain']
        if attack_chains:
            insights.append({
                'type': 'attack_chains',
                'title': 'Potential Attack Chains Identified',
                'description': f'Found {len(attack_chains)} potential attack chains',
                'details': [f'{" -> ".join(c.attack_path)}' for c in attack_chains[:3]],
                'priority': 'high'
            })
        
        # Temporal trends
        if target:
            temporal = self.get_temporal_analysis(target)
            if temporal and temporal.vulnerability_trends:
                most_common_vuln = max(temporal.vulnerability_trends.items(), key=lambda x: x[1])
                insights.append({
                    'type': 'temporal_trend',
                    'title': 'Vulnerability Trend Detected',
                    'description': f'Most common vulnerability: {most_common_vuln[0]} ({most_common_vuln[1]} instances)',
                    'details': [f'{k}: {v}' for k, v in list(temporal.vulnerability_trends.items())[:3]],
                    'priority': 'medium'
                })
        
        # Tool effectiveness
        tool_findings = defaultdict(list)
        for finding in self.vulnerability_findings:
            if not target or finding.target == target:
                tool_findings[finding.tool].append(finding)
        
        most_effective_tool = max(tool_findings.items(), key=lambda x: len(x[1])) if tool_findings else None
        if most_effective_tool:
            insights.append({
                'type': 'tool_effectiveness',
                'title': 'Most Effective Tool',
                'description': f'{most_effective_tool[0]} found {len(most_effective_tool[1])} vulnerabilities',
                'details': [f'{f.vulnerability_type} ({f.severity})' for f in most_effective_tool[1][:3]],
                'priority': 'low'
            })
        
        return insights
    
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
        self.vulnerability_findings = []
        self.knowledge_graph.clear()
        self.temporal_data.clear()
        self.correlation_cache.clear()
        self.insight_cache.clear()
        
        self._scan_and_index_files()
        if RAG_AVAILABLE:
            self._build_index()
            self._save_index()
            self._build_knowledge_graph()
            self._extract_vulnerabilities()
            self._analyze_temporal_patterns()
        debug_print(f"Index refreshed with {len(self.documents)} documents")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a comprehensive summary of the indexed data"""
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
        
        # Vulnerability statistics
        vuln_stats = {
            'total_findings': len(self.vulnerability_findings),
            'by_severity': Counter(f.severity for f in self.vulnerability_findings),
            'by_type': Counter(f.vulnerability_type for f in self.vulnerability_findings),
            'by_target': Counter(f.target for f in self.vulnerability_findings)
        }
        
        return {
            "total_documents": len(self.documents),
            "targets": targets,
            "tools": tools,
            "tool_counts": tool_counts,
            "target_counts": target_counts,
            "vulnerability_statistics": vuln_stats,
            "knowledge_graph_nodes": self.knowledge_graph.number_of_nodes(),
            "knowledge_graph_edges": self.knowledge_graph.number_of_edges(),
            "index_type": "semantic" if RAG_AVAILABLE else "text"
        }

    def _maybe_warn_and_prompt_rag_cleanup(self):
        num_docs = len(self.documents)
        total_bytes = sum(len(doc.content.encode('utf-8')) for doc in self.documents)
        total_mb = total_bytes / (1024*1024)
        if (num_docs > self.max_docs or total_mb > self.max_mb) and not self._warned_rag_session:
            print(f"\n⚠️  WARNING: RAG index is large: {num_docs} documents, {total_mb:.1f} MB (limits: {self.max_docs} docs, {self.max_mb} MB)")
            # List largest scan files
            scan_files = []
            for root, dirs, files in os.walk(self.scans_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if os.path.isfile(fpath):
                        stat = os.stat(fpath)
                        scan_files.append((stat.st_size, stat.st_mtime, fpath))
            scan_files = sorted(scan_files, reverse=True)
            print("Largest scan files:")
            for size, mtime, path in scan_files[:5]:
                print(f"  {os.path.basename(path)} - {size/(1024*1024):.1f} MB")
            resp = input("Do you want to clean up old scan results now? (y/N): ").strip().lower()
            if resp == 'y':
                # Delete oldest files until under limit
                scan_files_by_age = sorted(scan_files, key=lambda x: x[1])
                cur_docs = num_docs
                cur_mb = total_mb
                deleted = []
                for size, mtime, path in scan_files_by_age:
                    if cur_docs <= self.max_docs and cur_mb <= self.max_mb:
                        break
                    try:
                        os.remove(path)
                        cur_mb -= size/(1024*1024)
                        deleted.append(path)
                        print(f"Deleted {os.path.basename(path)}")
                    except Exception as e:
                        print(f"Failed to delete {path}: {e}")
                print(f"Cleanup complete. RAG index now {cur_docs} docs, {cur_mb:.1f} MB.")
            else:
                print("No cleanup performed. You may encounter this warning again.")
                self._warned_rag_session = True

# Backward compatibility
ScanRAG = EnhancedScanRAG

# Backward compatibility
ScanRAG = EnhancedScanRAG 