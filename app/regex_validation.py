import re
import ipaddress

# functions to ensure the necessary valid patterns are entered by user
def hash_validity(hash_type, file_hash):
    patterns = {
        "md5": r"^[a-fA-F0-9]{32}$",
        "sha1": r"^[a-fA-F0-9]{40}$",
        "sha256": r"^[a-fA-F0-9]{64}$"
    }
    pattern = patterns.get(hash_type.lower())
    return bool(re.fullmatch(pattern, file_hash)) if pattern else False
    
def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def valid_domain(domain):
    # Very basic domain regex — you can improve it if needed
    domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    return bool(re.fullmatch(domain_regex, domain))

def valid_url(url):
    url_regex = r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
    return bool(re.fullmatch(url_regex, url))
