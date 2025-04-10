from typing import List, Dict, Any
import os

def get_file_size(file_path: str) -> int:
    """Get file size in bytes"""
    return os.path.getsize(file_path)

def chunk_document(file_path: str, chunk_size: int = 100000, overlap: int = 1000) -> List[str]:
    """Split a document into manageable chunks"""
    chunks = []
    
    # Get file size
    file_size = get_file_size(file_path)
    
    # If file is small enough, just read it all
    if file_size < chunk_size:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            return [f.read()]
    
    # For larger files, read in chunks with overlap
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        overlap_text = ""
        while True:
            # Read chunk plus overlap
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            # Combine with previous overlap
            combined_chunk = overlap_text + chunk
            
            # Save for next iteration (if possible)
            if len(chunk) >= overlap:
                overlap_text = chunk[-overlap:]
            else:
                overlap_text = chunk
            
            chunks.append(combined_chunk)
    
    return chunks

def find_natural_break(text: str, position: int, window: int = 100) -> int:
    """Find a natural break point (period, new line, etc.) near the position"""
    # Define potential breaking characters
    break_chars = ['.', '!', '?', '\n', '\r', '\t']
    
    # Set search window
    start = max(0, position - window)
    end = min(len(text), position + window)
    search_text = text[start:end]
    
    # Look for breaks after the position first
    for i, char in enumerate(search_text[position-start:]):
        if char in break_chars:
            return position + i + 1
    
    # Then look before the position
    for i in range(position-start, 0, -1):
        if search_text[i-1] in break_chars:
            return start + i
    
    # If no natural break is found, just return the original position
    return position
