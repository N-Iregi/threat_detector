import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from query_ioc import get_recent_iocs
from get_ioc_byID import search_ioc_by_id
from search_ioc_keyword import search_ioc_by_keyword
from search_ioc_hash import search_by_file_hash
from get_malware_list import get_malware_list
from iocs_malware_fam import search_ioc_by_malware
from share_IOC import submit_ioc

# Wrapper to fetch recent IOCs (pass days as argument)
def fetch_recent_iocs(days=3):
    from api_client_details import threatfox_post
    if not (1 <= days <= 7):
        raise ValueError("Days must be between 1 and 7.")
    query_params = {"query": "get_iocs", "days": days}
    return threatfox_post(query_params)

# Wrapper to get IOC by ID
def fetch_ioc_by_id(ioc_id):
    from api_client_details import threatfox_post
    if not str(ioc_id).isdigit():
        raise ValueError("IOC ID must be numeric.")
    query_params = {"query": "ioc", "id": str(ioc_id)}
    return threatfox_post(query_params)

# Wrapper to search by keyword (IP/Domain)
def fetch_ioc_by_keyword(keyword, exact_match=False):
    from api_client_details import threatfox_post
    from regex_validation import valid_ip, valid_domain
    if not (valid_ip(keyword) or valid_domain(keyword)):
        raise ValueError("Keyword must be a valid IP address or domain.")
    query_params = {
        "query": "search_ioc",
        "search_term": keyword,
        "exact_match": str(exact_match).lower(),
    }
    return threatfox_post(query_params)

# Wrapper to search IOCs by file hash
def fetch_iocs_by_hash(file_hash):
    from api_client_details import threatfox_post
    from regex_validation import hash_validity
    if not hash_validity(file_hash):
        raise ValueError("Invalid file hash format.")
    query_params = {"query": "search_hash", "hash": file_hash}
    return threatfox_post(query_params)

# Wrapper to list malware families
def fetch_malware_list():
    from api_client_details import threatfox_post
    return threatfox_post({"query": "malware_list"})

# Wrapper to get IOCs by malware family name
def fetch_iocs_by_malware_family(family, limit=50):
    from api_client_details import threatfox_post
    if not family:
        raise ValueError("Malware family name is required.")
    if not (1 <= limit <= 1000):
        raise ValueError("Limit must be between 1 and 1000.")
    query_params = {
        "query": "malwareinfo",
        "malware": family,
        "limit": limit,
    }
    return threatfox_post(query_params)

# Wrapper to submit a new IOC
def submit_new_ioc(ioc_type, iocs, threat_type, malware, confidence, comment=""):
    from api_client_details import threatfox_post
    from regex_validation import valid_domain, valid_ip, valid_url, hash_validity

    if not all([ioc_type, iocs, threat_type, malware]):
        raise ValueError("All required fields must be filled.")

    if not isinstance(confidence, int) or not (0 <= confidence <= 100):
        raise ValueError("Confidence must be an integer between 0 and 100.")

    # Validate IOC
    if ioc_type == "domain" and not valid_domain(iocs):
        raise ValueError("Invalid domain format.")
    elif ioc_type == "ip" and not valid_ip(iocs):
        raise ValueError("Invalid IP format.")
    elif ioc_type == "url" and not valid_url(iocs):
        raise ValueError("Invalid URL format.")
    elif ioc_type in ["md5", "sha1", "sha256"] and not hash_validity(iocs):
        raise ValueError("Invalid file hash format.")

    query_params = {
        "query": "submit_ioc",
        "ioc_type": ioc_type,
        "iocs": [iocs],
        "threat_type": threat_type,
        "malware": malware,
        "confidence_level": confidence,
        "comment": comment,
    }
    return threatfox_post(query_params)

# Create a handler to route HTTP requests to the above functions
class RequestHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        # Parse query parameters
        path = self.path.split('?')[0]
        query_params = parse_qs(urlparse(self.path).query)
        
        # Determine which function to call based on URL path
        if path == "/recent_iocs":
            days = int(query_params.get('days', [3])[0])  # Default to 3 days
            response = fetch_recent_iocs(days)
        elif path == "/ioc_by_id":
            ioc_id = query_params.get('id', [None])[0]
            if ioc_id:
                response = fetch_ioc_by_id(ioc_id)
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error: Missing IOC ID.")
                return
        elif path == "/ioc_by_keyword":
            keyword = query_params.get('keyword', [None])[0]
            exact_match = query_params.get('exact_match', ['false'])[0].lower() == 'true'
            if keyword:
                response = fetch_ioc_by_keyword(keyword, exact_match)
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error: Missing keyword.")
                return
        elif path == "/malware_list":
            response = fetch_malware_list()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Error: Endpoint not found.")
            return
        
        # Send response
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

# Start the HTTP server
def run(server_class=HTTPServer, handler_class=RequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run(port=8080)

