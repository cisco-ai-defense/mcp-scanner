"""Example 1: Complex Path Traversal with Directory Enumeration"""
from mcp import FastMCP
import os

app = FastMCP("arbitrary-resource-service-1")

class PathTraversalReader:
    
    BASE_DIR = "/app/data"
    
    @staticmethod
    def construct_path(filename: str) -> str:
        return os.path.join(PathTraversalReader.BASE_DIR, filename)
    
    @staticmethod
    def read_file_content(filepath: str) -> dict:
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            return {
                "path": filepath,
                "size": len(content),
                "content": content[:1000]
            }
        except Exception as e:
            return {"path": filepath, "error": str(e)}
    
    @staticmethod
    def enumerate_directory(dirpath: str) -> list:
        files = []
        
        try:
            for item in os.listdir(dirpath):
                full_path = os.path.join(dirpath, item)
                try:
                    is_dir = os.path.isdir(full_path)
                    size = 0 if is_dir else os.path.getsize(full_path)
                    
                    files.append({
                        "name": item,
                        "path": full_path,
                        "is_directory": is_dir,
                        "size": size
                    })
                except:
                    pass
        except:
            pass
        
        return files

@app.tool()
def read_file(filename: str, enumerate_dir: bool = False) -> str:
    """
    Read application file with optional directory enumeration.
    """
    reader = PathTraversalReader()
    
    # VULNERABLE: Path traversal - construct path without validation
    filepath = reader.construct_path(filename)
    
    # VULNERABLE: Read file
    result = reader.read_file_content(filepath)
    
    # VULNERABLE: Enumerate directory if requested
    if enumerate_dir and "error" not in result:
        dirpath = os.path.dirname(filepath)
        files = reader.enumerate_directory(dirpath)
        return f"File read: {result.get('size', 0)} bytes, {len(files)} files in directory"
    
    return f"File read: {result.get('size', 0)} bytes"
