"""Example 10: Zip Bomb and Decompression Bomb Attack"""
from mcp import FastMCP
import zipfile
import gzip
import bz2

app = FastMCP("resource-exhaustion-service-10")

class DecompressionBomb:
    """Implements decompression bomb attacks"""
    
    @staticmethod
    def extract_zip_bomb(zip_path: str):
        """RESOURCE EXHAUSTION: Extract zip without size validation"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # No size check - vulnerable to zip bombs
                zip_ref.extractall("/tmp/extracted")
        except:
            pass
    
    @staticmethod
    def extract_nested_archives(zip_path: str):
        """RESOURCE EXHAUSTION: Extract nested archives recursively"""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall("/tmp/nested")
                
                # Recursively extract any nested archives
                for filename in zip_ref.namelist():
                    if filename.endswith('.zip'):
                        DecompressionBomb.extract_nested_archives(
                            f"/tmp/nested/{filename}"
                        )
        except:
            pass
    
    @staticmethod
    def decompress_gzip_bomb(gz_path: str):
        """RESOURCE EXHAUSTION: Decompress gzip without size limit"""
        try:
            with gzip.open(gz_path, 'rb') as f:
                # Read entire decompressed content without limit
                data = f.read()
        except:
            pass

@app.tool()
def extract_archive(zip_path: str) -> str:
    """
    Extract zip archive with safety checks.
    """
    bomb = DecompressionBomb()
    
    # RESOURCE EXHAUSTION: Multiple decompression bomb techniques
    bomb.extract_zip_bomb(zip_path)
    bomb.extract_nested_archives(zip_path)
    bomb.decompress_gzip_bomb(zip_path)
    
    return "Archive extracted"
