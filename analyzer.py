#!/usr/bin/env python3
"""
ToolShell Honeypot - Analyzer Component
Deep analysis service for captured requests with tag-driven processing pipeline
"""

import os
import json
import time
import hashlib
import base64
import gzip
import yara
import re
from datetime import datetime
from pathlib import Path
import shutil
import traceback

# Configuration
DATA_DIR = os.environ.get('DATA_DIR', './data')
YARA_RULES_PATH = os.environ.get('YARA_RULES_PATH', '/app/yara_rules/')
SCAN_INTERVAL = float(os.environ.get('ANALYZER_SCAN_INTERVAL', '1.0'))  # seconds
MAX_PAYLOAD_SIZE = int(os.environ.get('MAX_PAYLOAD_SIZE', '10485760'))  # 10MB

# Directory paths
RAW_BODIES_DIR = os.path.join(DATA_DIR, 'raw_bodies')
EVENTS_NEW_DIR = os.path.join(DATA_DIR, 'events', 'new')
EVENTS_PROCESSED_DIR = os.path.join(DATA_DIR, 'events', 'processed')
EVENTS_ERROR_DIR = os.path.join(DATA_DIR, 'events', 'error')

def setup_directories():
    """Create required directory structure"""
    for directory in [RAW_BODIES_DIR, EVENTS_NEW_DIR, EVENTS_PROCESSED_DIR, EVENTS_ERROR_DIR]:
        os.makedirs(directory, exist_ok=True)
    print(f"[ANALYZER] Directory structure initialized in {DATA_DIR}")

def load_yara_rules():
    """Load YARA rules from the rules directory"""
    try:
        rule_files = []
        if os.path.exists(YARA_RULES_PATH):
            rule_files = [
                os.path.join(YARA_RULES_PATH, f) 
                for f in os.listdir(YARA_RULES_PATH) 
                if f.endswith('.yar')
            ]
        
        if rule_files:
            rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
            print(f"[ANALYZER] Loaded {len(rule_files)} YARA rule files")
            return rules
        else:
            print("[ANALYZER] No YARA rules found")
            return None
    except Exception as e:
        print(f"[ANALYZER] Error loading YARA rules: {e}")
        return None

class PayloadAnalyzer:
    """Core payload analysis engine with tag-driven processing"""
    
    def __init__(self, yara_rules):
        self.yara_rules = yara_rules
        
    def analyze_r7_payload(self, body_bytes, tags):
        """
        Analyze Metasploit R7 exploit payload
        Implements proper decompression: Gzip -> Base64 -> .NET gadget chain
        """
        results = {
            'r7_analysis': {
                'detected': False,
                'decompressed_payloads': [],
                'yara_matches_decompressed': []
            }
        }
        
        try:
            # Look for R7 exploit patterns in the body
            body_str = body_bytes.decode('utf-8', errors='ignore')
            
            # Pattern 1: MSOTlPn_DWP parameter containing gzipped+base64 data
            dwp_pattern = r'MSOTlPn_DWP=([^&\s]+)'
            dwp_matches = re.findall(dwp_pattern, body_str, re.IGNORECASE)
            
            for dwp_data in dwp_matches:
                try:
                    # URL decode first
                    import urllib.parse
                    dwp_decoded = urllib.parse.unquote_plus(dwp_data)
                    
                    # Look for Base64 patterns in the DWP data
                    b64_pattern = r'CompressedDataTable="([A-Za-z0-9+/=]+)"'
                    b64_matches = re.findall(b64_pattern, dwp_decoded)
                    
                    for b64_data in b64_matches:
                        try:
                            # Decode Base64
                            compressed_data = base64.b64decode(b64_data)
                            
                            # Decompress Gzip
                            decompressed_data = gzip.decompress(compressed_data)
                            
                            results['r7_analysis']['detected'] = True
                            results['r7_analysis']['decompressed_payloads'].append({
                                'size': len(decompressed_data),
                                'sha256': hashlib.sha256(decompressed_data).hexdigest()
                            })
                            
                            # YARA scan on decompressed data
                            if self.yara_rules:
                                yara_matches = self._scan_bytes_with_yara(decompressed_data)
                                if yara_matches:
                                    results['r7_analysis']['yara_matches_decompressed'].extend(yara_matches)
                            
                            print(f"[ANALYZER] R7 payload decompressed: {len(decompressed_data)} bytes")
                            
                        except Exception as e:
                            print(f"[ANALYZER] R7 decompression failed: {e}")
                            continue
                            
                except Exception as e:
                    print(f"[ANALYZER] R7 DWP processing failed: {e}")
                    continue
                    
        except Exception as e:
            print(f"[ANALYZER] R7 analysis error: {e}")
            
        return results
    
    def analyze_large_base64(self, body_bytes, tags):
        """Analyze large Base64 payloads with generic decoding attempts"""
        results = {
            'base64_analysis': {
                'candidates_found': 0,
                'decoded_payloads': [],
                'yara_matches_decoded': []
            }
        }
        
        try:
            body_str = body_bytes.decode('utf-8', errors='ignore')
            
            # Find Base64 candidates (40+ chars)
            b64_candidates = re.findall(r'([A-Za-z0-9+/=]{40,})', body_str)
            results['base64_analysis']['candidates_found'] = len(b64_candidates)
            
            for b64_candidate in b64_candidates[:10]:  # Limit to 10 candidates
                # Try different encodings
                for encoding in ['utf-8', 'utf-16le', 'ascii']:
                    try:
                        decoded_bytes = base64.b64decode(b64_candidate)
                        
                        # Heuristic: check if decoded content looks interesting
                        if len(decoded_bytes) > 10:
                            try:
                                decoded_str = decoded_bytes.decode(encoding, errors='ignore')
                                if self._is_interesting_content(decoded_str):
                                    results['base64_analysis']['decoded_payloads'].append({
                                        'encoding': encoding,
                                        'size': len(decoded_bytes),
                                        'preview': decoded_str[:100] if len(decoded_str) > 100 else decoded_str
                                    })
                                    
                                    # YARA scan on decoded content
                                    if self.yara_rules:
                                        yara_matches = self._scan_bytes_with_yara(decoded_bytes)
                                        if yara_matches:
                                            results['base64_analysis']['yara_matches_decoded'].extend(yara_matches)
                                    break
                            except:
                                # If string decoding fails, still check binary content
                                if self._is_interesting_binary(decoded_bytes):
                                    results['base64_analysis']['decoded_payloads'].append({
                                        'encoding': 'binary',
                                        'size': len(decoded_bytes),
                                        'preview': f"Binary data: {decoded_bytes[:20].hex()}"
                                    })
                                    
                                    # YARA scan on binary content
                                    if self.yara_rules:
                                        yara_matches = self._scan_bytes_with_yara(decoded_bytes)
                                        if yara_matches:
                                            results['base64_analysis']['yara_matches_decoded'].extend(yara_matches)
                                    break
                                    
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"[ANALYZER] Base64 analysis error: {e}")
            
        return results
    
    def _is_interesting_content(self, content_str):
        """Heuristic to determine if decoded content is interesting"""
        interesting_patterns = [
            'powershell', 'cmd.exe', 'system.', 'runtime', 'process',
            'invoke-', 'iex', 'frombase64string', 'downloadstring',
            'deserialize', 'binaryformatter', 'losformatter',
            'objectdataprovider', 'typeconfusedelegate'
        ]
        
        content_lower = content_str.lower()
        return any(pattern in content_lower for pattern in interesting_patterns)
    
    def _is_interesting_binary(self, binary_data):
        """Heuristic to determine if binary data is interesting"""
        # Check for common binary signatures
        signatures = [
            b'MZ',  # PE executable
            b'\x50\x4b',  # ZIP
            b'\x1f\x8b',  # GZIP
            b'<?xml',  # XML
            b'<html',  # HTML
        ]
        
        return any(binary_data.startswith(sig) for sig in signatures)
    
    def _scan_bytes_with_yara(self, data_bytes):
        """Scan bytes with YARA rules and return rule names"""
        try:
            matches = self.yara_rules.match(data=data_bytes)
            return [match.rule for match in matches]
        except Exception as e:
            print(f"[ANALYZER] YARA scan error: {e}")
            return []
    
    def scan_with_yara(self, body_path):
        """Scan file with YARA rules"""
        if not self.yara_rules:
            return []
            
        try:
            matches = self.yara_rules.match(body_path)
            return [match.rule for match in matches]
        except Exception as e:
            print(f"[ANALYZER] YARA file scan error: {e}")
            return []

def process_event(event_file, analyzer):
    """Process a single event file with comprehensive analysis"""
    event_path = os.path.join(EVENTS_NEW_DIR, event_file)
    processed_path = os.path.join(EVENTS_PROCESSED_DIR, event_file)
    error_path = os.path.join(EVENTS_ERROR_DIR, event_file)
    
    try:
        # Atomically move file to processed directory to claim it
        shutil.move(event_path, processed_path)
        
        # Load event data
        with open(processed_path, 'r', encoding='utf-8') as f:
            event_data = json.load(f)
        
        print(f"[ANALYZER] Processing event {event_data.get('id', 'unknown')}")
        
        # Initialize deep analysis results
        deep_analysis = {
            'analyzer_timestamp': datetime.utcnow().isoformat() + 'Z',
            'analyzer_version': '2.0.0',
            'yara_matches_raw': [],
            'total_analysis_time_ms': 0
        }
        
        start_time = time.time()
        
        # Load request body if available
        body_hash = event_data.get('body_hash')
        body_bytes = b''
        
        if body_hash:
            body_path = os.path.join(RAW_BODIES_DIR, f"{body_hash}.bin")
            if os.path.exists(body_path):
                with open(body_path, 'rb') as f:
                    body_bytes = f.read()
                
                # Always perform YARA scan on raw payload
                deep_analysis['yara_matches_raw'] = analyzer.scan_with_yara(body_path)
        
        # Tag-driven analysis pipeline
        tags = event_data.get('tags', [])
        
        # R7 Metasploit exploit analysis
        if any('PATTERN:R7_PAYLOAD' in tag for tag in tags):
            r7_results = analyzer.analyze_r7_payload(body_bytes, tags)
            deep_analysis.update(r7_results)
        
        # Large Base64 analysis
        if any('HEURISTIC:LARGE_B64' in tag for tag in tags):
            b64_results = analyzer.analyze_large_base64(body_bytes, tags)
            deep_analysis.update(b64_results)
        
        # Calculate analysis time
        analysis_time = (time.time() - start_time) * 1000
        deep_analysis['total_analysis_time_ms'] = round(analysis_time, 2)
        
        # Add deep analysis results to event
        event_data['deep_analysis_results'] = deep_analysis
        
        # Save enriched event
        with open(processed_path, 'w', encoding='utf-8') as f:
            json.dump(event_data, f, indent=2)
        
        print(f"[ANALYZER] Completed analysis for {event_data.get('id')} in {analysis_time:.1f}ms")
        
    except Exception as e:
        print(f"[ANALYZER] Error processing {event_file}: {e}")
        traceback.print_exc()
        
        # Move to error directory
        try:
            if os.path.exists(processed_path):
                shutil.move(processed_path, error_path)
            elif os.path.exists(event_path):
                shutil.move(event_path, error_path)
        except:
            pass

def main():
    """Main analyzer loop"""
    print("[ANALYZER] ToolShell Honeypot Analyzer starting...")
    
    # Setup
    setup_directories()
    yara_rules = load_yara_rules()
    analyzer = PayloadAnalyzer(yara_rules)
    
    print(f"[ANALYZER] Scanning for events every {SCAN_INTERVAL}s")
    print(f"[ANALYZER] Watching directory: {EVENTS_NEW_DIR}")
    
    # Main processing loop
    while True:
        try:
            # Scan for new events
            event_files = [
                f for f in os.listdir(EVENTS_NEW_DIR) 
                if f.endswith('.json')
            ]
            
            if event_files:
                print(f"[ANALYZER] Found {len(event_files)} events to process")
                
                for event_file in sorted(event_files):
                    process_event(event_file, analyzer)
            
            time.sleep(SCAN_INTERVAL)
            
        except KeyboardInterrupt:
            print("[ANALYZER] Shutdown requested")
            break
        except Exception as e:
            print(f"[ANALYZER] Main loop error: {e}")
            traceback.print_exc()
            time.sleep(5)  # Wait before retrying

if __name__ == '__main__':
    main() 