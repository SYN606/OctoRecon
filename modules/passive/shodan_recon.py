import socket
from urllib.parse import urlparse
from typing import TYPE_CHECKING
import config

from core.base_module import BaseModule
from core.schemas import ModuleResult

if TYPE_CHECKING:
    from core.scanner import Scanner

class ShodanRecon(BaseModule):
    name = "Shodan Intelligence"
    category = "Passive"
    description = "Analyzes the target IP using Shodan to find open ports, ISP data, and known vulnerabilities (CVEs)."
    max_score = 20

    async def run(self, scanner: 'Scanner') -> ModuleResult:
        result = ModuleResult(module_name=self.name, max_score=self.max_score)
        
        # 1. Check for API Key in the environment
        api_key = getattr(config, "SHODAN_API_KEY", None)
        if not api_key:
            result.description = "Skipped: No SHODAN_API_KEY found in .env file."
            result.score = self.max_score # Don't penalize if skipped
            return result

        # 2. Resolve target domain to an IP address (Shodan API requirement)
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

        # 3. Query Shodan API
        shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            # We use scanner.client so it inherits our Semaphore (rate limiting) and Timeouts
            response = await scanner.client.get(shodan_url)
        except Exception as e:
            result.description = f"Shodan API request failed: {e}"
            result.score = 0
            return result
            
        # 4. Handle API Errors gracefully
        if response.status_code == 401:
            result.description = "Invalid Shodan API Key."
            result.score = 0
            return result
        elif response.status_code == 404:
            result.description = f"No historical Shodan data found for IP: {ip}"
            result.score = self.max_score
            return result
        elif response.status_code == 429:
            result.description = "Shodan API rate limit exceeded."
            result.score = 0
            return result
        elif response.status_code != 200:
            result.description = f"Shodan API error (HTTP {response.status_code})"
            result.score = 0
            return result
            
        # 5. Parse Intelligence Data
        data = response.json()
        ports = data.get("ports", [])
        org = data.get("org", "Unknown")
        isp = data.get("isp", "Unknown")
        vulns = data.get("vulns", [])
        
        # Append data perfectly formatted for the V2 Pydantic schema
        result.data.append({"Property": "Target IP", "Value": ip})
        result.data.append({"Property": "Organization", "Value": org})
        result.data.append({"Property": "ISP", "Value": isp})
        result.data.append({"Property": "Open Ports", "Value": ", ".join(map(str, ports)) if ports else "None"})
        
        # 6. Intelligent Scoring System
        score = self.max_score
        
        if vulns:
            result.data.append({"Property": "Vulnerabilities (CVEs)", "Value": ", ".join(vulns)})
            score = max(0, score - (len(vulns) * 5)) # Heavily penalize for missing patches/CVEs
            
        if ports:
            # Penalize slightly for every open port beyond standard web ports (80, 443)
            non_standard_ports = [p for p in ports if p not in [80, 443, 8080, 8443]]
            if non_standard_ports:
                score = max(0, score - len(non_standard_ports))
        
        result.score = score
        result.description = f"Analyzed {ip}: Found {len(ports)} open ports and {len(vulns)} known CVEs."
        
        return result
