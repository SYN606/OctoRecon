"""
Module Loader
Author : 0ct0pu3
VERSION : 1.0.0

Loads all OctoRecon scanner modules.
"""

# ----------------------------
# Passive Modules
# ----------------------------

from modules.headers import HeaderScanner
from modules.ssl import SSLScanner
from modules.dns import DNSScanner
from modules.methods import MethodScanner
from modules.cookies import CookieScanner
from modules.redirects import RedirectScanner
from modules.tech import TechnologyScanner
from modules.whois_lookup import WhoisScanner
from modules.broken_links import BrokenLinkScanner


# New Passive Modules
from modules.passive.robots import Module as RobotsScanner
from modules.passive.securitytxt import Module as SecurityTxtScanner
from modules.passive.sitemap import Module as SitemapScanner
from modules.passive.javascript import Module as JavaScriptScanner
from modules.passive.emails import Module as EmailScanner
from modules.passive.subdomains import Module as SubdomainScanner
from modules.passive.wayback import Module as Wayback

from modules.security.csp import Module as CSPScanner

# ----------------------------
# Registered Modules
# ----------------------------

MODULES = [

    # Passive Recon
    HeaderScanner(),
    SSLScanner(),
    DNSScanner(),
    MethodScanner(),
    CookieScanner(),
    RedirectScanner(),
    TechnologyScanner(),
    WhoisScanner(),
    BrokenLinkScanner(),
    RobotsScanner(),
    SecurityTxtScanner(),
    SitemapScanner(),
    JavaScriptScanner(),
    EmailScanner(),
    SubdomainScanner(),
    Wayback(),

    # Security
    CSPScanner(),

]