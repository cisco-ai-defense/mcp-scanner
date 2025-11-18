"""Example 5: Complex LDAP Injection with Dynamic Filter Building"""
from mcp import FastMCP

app = FastMCP("injection-attacks-service-5")

class LDAPSearcher:
    """Handles LDAP directory searches"""
    def __init__(self, server_url: str = "ldap://localhost"):
        self.server_url = server_url
        self.base_dn = "dc=example,dc=com"
    
    def build_filter(self, criteria: dict, match_all: bool = True) -> str:
        """Build LDAP search filter from criteria"""
        filters = []
        
        for key, value in criteria.items():
            # VULNERABLE: No escaping of special LDAP characters
            filters.append(f"({key}={value})")
        
        if len(filters) == 0:
            return "(objectClass=*)"
        elif len(filters) == 1:
            return filters[0]
        else:
            operator = "&" if match_all else "|"
            return f"({operator}{''.join(filters)})"
    
    def search(self, search_filter: str, attributes: list = None, 
              scope: str = "subtree") -> list:
        """Execute LDAP search"""
        import ldap
        
        try:
            conn = ldap.initialize(self.server_url)
            conn.simple_bind_s()
            
            scope_map = {
                "base": ldap.SCOPE_BASE,
                "onelevel": ldap.SCOPE_ONELEVEL,
                "subtree": ldap.SCOPE_SUBTREE
            }
            
            ldap_scope = scope_map.get(scope, ldap.SCOPE_SUBTREE)
            
            # VULNERABLE: Unsanitized filter passed to search
            results = conn.search_s(self.base_dn, ldap_scope, search_filter, attributes)
            
            conn.unbind_s()
            return results
        except Exception as e:
            return []

@app.tool()
def search_users(username: str = "",
                email: str = "",
                department: str = "",
                match_all: bool = True,
                include_groups: bool = False) -> str:
    """
    Search LDAP directory for users with flexible filtering.
    """
    searcher = LDAPSearcher()
    
    # Build search criteria
    criteria = {}
    
    if username:
        criteria["uid"] = username
    
    if email:
        criteria["mail"] = email
    
    if department:
        criteria["ou"] = department
    
    # VULNERABLE: LDAP injection through filter building
    # User can inject: "admin)(|(uid=*" to bypass filters
    # Or: "*)(objectClass=*))(&(objectClass=void" for authentication bypass
    search_filter = searcher.build_filter(criteria, match_all)
    
    # Add group filter if requested
    if include_groups:
        search_filter = f"(|{search_filter}(objectClass=groupOfNames))"
    
    # Execute search
    results = searcher.search(search_filter)
    
    return f"Found {len(results)} entries matching filter: {search_filter}"
