import socket
from urllib.parse import urlparse
from typing import TYPE_CHECKING
import config

from core.base_module import BaseModule
from core.schemas import ModuleResult

if TYPE_CHECKING:
    from core.scanner import Scanner

class IPInfoRecon(BaseModule):
    name = "Server Location (IPInfo)"
    category = "Passive"
    description = "Gathers geographical location, ASN, and hosting provider information for the target server."
    max_score = 20

    async def run(self, scanner: 'Scanner') -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=self.max_score)
        
        # 1. Resolve Target Domain to IP
        parsed = urlparse(scanner.target)
        hostname = parsed.hostname
        if not hostname:
            result.description = "Failed to parse target hostname."
            result.score = 0
            return result
            
        try:
            ip = socket.gethostbyname(hostname)
        except Exception as e:
            result.description = f"Failed to resolve IP: {e}"
            result.score = 0
            return result

        # 2. Query IPInfo.io (Works without an API key up to 1,000 req/day)
        url = f"https://ipinfo.io/{ip}/json"
        
        # Check if user added a token in config just in case, but it's not required
        token = getattr(config, "IPINFO_TOKEN", None)
        if token:
            url += f"?token={token}"

        try:
            response = await scanner.client.get(url)
        except Exception as e:
            result.description = f"IPInfo request failed: {e}"
            result.score = 0
            return result
            
        if response.status_code == 429:
            result.description = "IPInfo rate limit exceeded (1,000 requests/day free tier hit)."
            result.score = 0
            return result
        elif response.status_code != 200:
            result.description = f"IPInfo API error (HTTP {response.status_code})"
            result.score = 0
            return result
            
        data = response.json()
        
        # 3. Map JSON data to the V2 reporting schema
        fields = ["ip", "hostname", "city", "region", "country", "loc", "org", "timezone", "postal"]
        for field in fields:
            if field in data and data[field]:
                # Format property names nicely for the UI Table
                prop_name = field.capitalize()
                if field == "ip": prop_name = "IP Address"
                if field == "loc": prop_name = "Coordinates (Lat, Long)"
                if field == "org": prop_name = "Organization / ASN"
                
                result.data.append({"Property": prop_name, "Value": data[field]})
        
        # 4. Intelligence Scoring Logic
        org = data.get("org", "").lower()
        is_cloud = any(x in org for x in ["cloudflare", "amazon", "aws", "google", "fastly", "akamai", "microsoft", "azure", "digitalocean", "linode"])
        
        if is_cloud:
            result.description = f"Server is hosted behind a Cloud/CDN provider ({data.get('org')}). True origin IP may be hidden."
            result.score = self.max_score # Origin protection is good security practice
        else:
            result.description = f"Server is directly exposed. Hosted by {data.get('org', 'Unknown')} in {data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}."
            result.score = max(0, self.max_score - 5) # Slight penalty for exposing the raw backend server to the public
            
        return result
