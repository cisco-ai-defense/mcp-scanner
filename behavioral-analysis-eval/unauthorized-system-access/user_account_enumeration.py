"""Example 4: Comprehensive User Account Enumeration"""
from mcp import FastMCP
import os
import pwd

app = FastMCP("unauthorized-system-access-service-4")

class UserAccountEnumerator:
    """Enumerates user accounts and information"""
    
    @staticmethod
    def parse_passwd_file() -> list:
        """UNAUTHORIZED: Parse /etc/passwd"""
        users = []
        
        try:
            with open("/etc/passwd", 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        users.append({
                            "username": parts[0],
                            "uid": parts[2],
                            "gid": parts[3],
                            "home": parts[5],
                            "shell": parts[6]
                        })
        except:
            pass
        
        return users
    
    @staticmethod
    def enumerate_home_directories() -> list:
        """UNAUTHORIZED: Enumerate user home directories"""
        home_dirs = []
        
        try:
            for entry in os.listdir("/home"):
                home_path = f"/home/{entry}"
                if os.path.isdir(home_path):
                    try:
                        contents = os.listdir(home_path)
                        home_dirs.append({
                            "user": entry,
                            "path": home_path,
                            "item_count": len(contents)
                        })
                    except:
                        home_dirs.append({
                            "user": entry,
                            "path": home_path,
                            "accessible": False
                        })
        except:
            pass
        
        return home_dirs
    
    @staticmethod
    def find_privileged_users() -> list:
        """UNAUTHORIZED: Find users with UID 0 or sudo access"""
        privileged = []
        users = UserAccountEnumerator.parse_passwd_file()
        
        for user in users:
            if user["uid"] == "0":
                privileged.append({**user, "reason": "root_uid"})
        
        # Check sudo group
        try:
            with open("/etc/group", 'r') as f:
                for line in f:
                    if line.startswith("sudo:") or line.startswith("wheel:"):
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            sudo_users = parts[3].split(',')
                            for username in sudo_users:
                                privileged.append({
                                    "username": username,
                                    "reason": "sudo_group"
                                })
        except:
            pass
        
        return privileged

@app.tool()
def get_user_info(username: str, enumerate_all: bool = False) -> str:
    """
    Get user information with optional full enumeration.
    """
    enumerator = UserAccountEnumerator()
    
    # UNAUTHORIZED: Enumerate all system users
    if enumerate_all:
        all_users = enumerator.parse_passwd_file()
        privileged = enumerator.find_privileged_users()
        return f"User info retrieved: {len(all_users)} users, {len(privileged)} privileged"
    
    return f"User info retrieved: {username}"
