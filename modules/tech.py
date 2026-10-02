"""
Technology Detection
Author : 0ct0pu3
VERSION : 1.0.0
"""

from __future__ import annotations
import base64
import re
import uuid

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from rich.table import Table

from core.base_module import BaseModule
from core.report_schema import Report

# ==========================================================
# Technology Object
# ==========================================================


@dataclass
class Technology:

    name: str

    category: str

    version: str = "-"

    confidence: int = 0

    evidence: list[str] = field(default_factory=list)


# ==========================================================
# Header Signatures (regex match against a specific header)
# Categories: Web Server, Backend
# ==========================================================

HEADER_SIGNATURES = {
    "Server": {
        "Apache": {
            "category": "Web Server",
            "pattern": r"Apache/?([\d\.]+)?",
        },
        "Nginx": {
            "category": "Web Server",
            "pattern": r"nginx/?([\d\.]+)?",
        },
        "Microsoft IIS": {
            "category": "Web Server",
            "pattern": r"Microsoft-IIS/?([\d\.]+)?",
        },
        "LiteSpeed": {
            "category": "Web Server",
            "pattern": r"LiteSpeed/?([\d\.]+)?",
        },
        "Caddy": {
            "category": "Web Server",
            "pattern": r"Caddy/?([\d\.]+)?",
        },
        "OpenResty": {
            "category": "Web Server",
            "pattern": r"openresty/?([\d\.]+)?",
        },
        "Apache Tomcat": {
            "category": "Web Server",
            "pattern": r"(?:Apache-)?Tomcat/?([\d\.]+)?",
        },
        "Jetty": {
            "category": "Web Server",
            "pattern": r"Jetty\(?([\d\.]+)?",
        },
        "Cowboy": {
            "category": "Web Server",
            "pattern": r"Cowboy",
        },
        "Gunicorn": {
            "category": "Web Server",
            "pattern": r"gunicorn/?([\d\.]+)?",
        },
        "uWSGI": {
            "category": "Web Server",
            "pattern": r"uWSGI",
        },
        "Kestrel": {
            "category": "Web Server",
            "pattern": r"Kestrel",
        },
        "Google Frontend": {
            "category": "Web Server",
            "pattern": r"\bgws\b",
        },
        "Amazon S3": {
            "category": "Hosting",
            "pattern": r"AmazonS3",
        },
        "Werkzeug": {
            "category": "Backend",
            "pattern": r"Werkzeug/?([\d\.]+)?",
        },
        "uvicorn": {
            "category": "Backend",
            "pattern": r"uvicorn",
        },
        "Cloudflare": {
            "category": "CDN",
            "pattern": r"cloudflare",
        },
        "DDoS-Guard": {
            "category": "WAF",
            "pattern": r"ddos-guard",
        },
    },
    "X-Powered-By": {
        "PHP": {
            "category": "Backend",
            "pattern": r"PHP/?([\d\.]+)?",
        },
        "ASP.NET": {
            "category": "Backend",
            "pattern": r"ASP\.NET",
        },
        "Express": {
            "category": "Backend",
            "pattern": r"Express",
        },
        "Next.js": {
            "category": "Frontend Framework",
            "pattern": r"Next\.js",
        },
        "Phusion Passenger": {
            "category": "Backend",
            "pattern": r"Phusion Passenger",
        },
    },
    "Via": {
        "Heroku": {
            "category": "Hosting",
            "pattern": r"vegur",
        },
        "Varnish": {
            "category": "CDN",
            "pattern": r"varnish",
        },
    },
}

# ==========================================================
# Presence Header Signatures — detected purely by the header
# key existing, regardless of its value.
# Categories: CDN, Hosting, WAF, Security
# ==========================================================

PRESENCE_HEADER_SIGNATURES = {
    "CF-Ray": ("Cloudflare", "CDN"),
    "X-Amz-Cf-Id": ("Amazon CloudFront", "CDN"),
    "X-Akamai-Transformed": ("Akamai", "CDN"),
    "X-Fastly-Request-ID": ("Fastly", "CDN"),
    "X-Served-By": ("Fastly", "CDN"),
    "X-Vercel-Id": ("Vercel", "Hosting"),
    "X-Vercel-Cache": ("Vercel", "Hosting"),
    "X-Nf-Request-Id": ("Netlify", "Hosting"),
    "X-Github-Request-Id": ("GitHub Pages", "Hosting"),
    "X-Sucuri-ID": ("Sucuri", "WAF"),
    "X-Sucuri-Cache": ("Sucuri", "WAF"),
    "X-Iinfo": ("Imperva Incapsula", "WAF"),
    "X-Firewall-Protection": ("Generic Firewall", "WAF"),
    "Strict-Transport-Security": ("HSTS", "Security"),
    "Content-Security-Policy": ("Content Security Policy", "Security"),
    "X-Frame-Options": ("Clickjacking Protection", "Security"),
    "Permissions-Policy": ("Permissions Policy", "Security"),
}

# ==========================================================
# Reverse Proxy Signatures
# Regex match against specific HTTP headers
# Categories: Reverse Proxy
# ==========================================================

REVERSE_PROXY_SIGNATURES = {
    "Server": {
        "Envoy": {
            "category": "Reverse Proxy",
            "pattern": r"envoy",
        },
        "HAProxy": {
            "category": "Reverse Proxy",
            "pattern": r"haproxy/?([\d\.]+)?",
        },
        "Traefik": {
            "category": "Reverse Proxy",
            "pattern": r"traefik/?([\d\.]+)?",
        },
        "Varnish": {
            "category": "Reverse Proxy",
            "pattern": r"varnish/?([\d\.]+)?",
        },
        "Squid": {
            "category": "Reverse Proxy",
            "pattern": r"squid/?([\d\.]+)?",
        },
        "Apache Traffic Server": {
            "category": "Reverse Proxy",
            "pattern": r"(?:ATS|ApacheTrafficServer)/?([\d\.]+)?",
        },
        "OpenResty": {
            "category": "Reverse Proxy",
            "pattern": r"openresty/?([\d\.]+)?",
        },
    },
    "Via": {
        "Varnish": {
            "category": "Reverse Proxy",
            "pattern": r"varnish",
        },
        "Squid": {
            "category": "Reverse Proxy",
            "pattern": r"squid",
        },
    },
    "X-Served-By": {
        "Varnish": {
            "category": "Reverse Proxy",
            "pattern": r".+",
        },
    },
}

# ==========================================================
# CDN Signatures
# ==========================================================

CDN_SIGNATURES = {
    "Server": {
        "Cloudflare": {
            "category": "CDN",
            "pattern": r"cloudflare",
        },
        "Akamai": {
            "category": "CDN",
            "pattern": r"akamai",
        },
        "Fastly": {
            "category": "CDN",
            "pattern": r"fastly",
        },
    },
    "Via": {
        "CloudFront": {
            "category": "CDN",
            "pattern": r"cloudfront",
        },
        "Fastly": {
            "category": "CDN",
            "pattern": r"fastly",
        },
        "Akamai": {
            "category": "CDN",
            "pattern": r"akamai",
        },
    },
    "X-Cache": {
        "CloudFront": {
            "category": "CDN",
            "pattern": r"cloudfront",
        },
        "Fastly": {
            "category": "CDN",
            "pattern": r"fastly",
        },
    },
    "CF-Ray": {
        "Cloudflare": {
            "category": "CDN",
            "pattern": r".+",
        },
    },
    "CF-Cache-Status": {
        "Cloudflare": {
            "category": "CDN",
            "pattern": r".+",
        },
    },
    "X-Amz-Cf-Id": {
        "Amazon CloudFront": {
            "category": "CDN",
            "pattern": r".+",
        },
    },
    "X-Akamai-Transformed": {
        "Akamai": {
            "category": "CDN",
            "pattern": r".+",
        },
    },
    "X-Fastly-Request-ID": {
        "Fastly": {
            "category": "CDN",
            "pattern": r".+",
        },
    },
    "X-Served-By": {
        "Fastly": {
            "category": "CDN",
            "pattern": r".*cache.*",
        },
    },
}

# ==========================================================
# WAF Signatures
# ==========================================================

WAF_SIGNATURES = {
    "Server": {
        "Cloudflare": {
            "category": "WAF",
            "pattern": r"cloudflare",
        },
        "Sucuri": {
            "category": "WAF",
            "pattern": r"sucuri",
        },
        "Akamai": {
            "category": "WAF",
            "pattern": r"akamai",
        },
        "Imperva": {
            "category": "WAF",
            "pattern": r"imperva|incapsula",
        },
        "F5 BIG-IP": {
            "category": "WAF",
            "pattern": r"bigip|f5",
        },
        "FortiWeb": {
            "category": "WAF",
            "pattern": r"fortiweb",
        },
        "Barracuda": {
            "category": "WAF",
            "pattern": r"barracuda",
        },
        "Azure WAF": {
            "category": "WAF",
            "pattern": r"microsoft-azure-application-gateway",
        },
        "AWS WAF": {
            "category": "WAF",
            "pattern": r"awselb|aws",
        },
        "DDoS-Guard": {
            "category": "WAF",
            "pattern": r"ddos-guard",
        },
    },
    "X-CDN": {
        "Cloudflare": {
            "category": "WAF",
            "pattern": r"cloudflare",
        },
    },
    "X-Sucuri-ID": {
        "Sucuri": {
            "category": "WAF",
            "pattern": r".+",
        },
    },
    "X-Iinfo": {
        "Imperva": {
            "category": "WAF",
            "pattern": r".+",
        },
    },
    "X-Azure-Ref": {
        "Azure WAF": {
            "category": "WAF",
            "pattern": r".+",
        },
    },
    "CF-Ray": {
        "Cloudflare": {
            "category": "WAF",
            "pattern": r".+",
        },
    },
    "CF-Cache-Status": {
        "Cloudflare": {
            "category": "WAF",
            "pattern": r".+",
        },
    },
    "X-Firewall": {
        "Generic WAF": {
            "category": "WAF",
            "pattern": r".+",
        },
    },
}

# ==========================================================
# CMS / Framework Signatures
# ==========================================================

CMS_SIGNATURES = {
    "Meta Generator": {
        "WordPress": {
            "category": "CMS",
            "pattern": r"wordpress\s*([0-9.]+)?",
        },
        "Joomla": {
            "category": "CMS",
            "pattern": r"joomla!?[\s/]?([0-9.]+)?",
        },
        "Drupal": {
            "category": "CMS",
            "pattern": r"drupal\s*([0-9.]+)?",
        },
        "Magento": {
            "category": "CMS",
            "pattern": r"magento\s*([0-9.]+)?",
        },
        "Ghost": {
            "category": "CMS",
            "pattern": r"ghost",
        },
        "Blogger": {
            "category": "CMS",
            "pattern": r"blogger",
        },
        "Wix": {
            "category": "CMS",
            "pattern": r"wix",
        },
        "Shopify": {
            "category": "CMS",
            "pattern": r"shopify",
        },
    },
    "X-Powered-By": {
        "ASP.NET": {
            "category": "Framework",
            "pattern": r"ASP\.NET",
        },
        "Laravel": {
            "category": "Framework",
            "pattern": r"Laravel",
        },
        "Express": {
            "category": "Framework",
            "pattern": r"Express",
        },
        "PHP": {
            "category": "Language",
            "pattern": r"PHP/?([0-9.]+)?",
        },
    },
    "HTML": {
        "WordPress": {
            "category": "CMS",
            "pattern": r"wp-content|wp-includes|wp-json",
        },
        "Joomla": {
            "category": "CMS",
            "pattern": r"/media/system/|joomla!",
        },
        "Drupal": {
            "category": "CMS",
            "pattern":
            r"drupal-settings-json|sites/default/files|Drupal.settings",
        },
        "Magento": {
            "category": "CMS",
            "pattern": r"mage/cookies|Magento_Ui|static/version",
        },
        "Shopify": {
            "category": "CMS",
            "pattern":
            r"cdn\.shopify\.com|Shopify.theme|shopify-payment-button",
        },
        "Wix": {
            "category": "CMS",
            "pattern": r"static\.wixstatic\.com|wix-code-sdk|wix-image",
        },
        "Blogger": {
            "category": "CMS",
            "pattern": r"blogger.googleusercontent.com|blogger",
        },
        "Ghost": {
            "category": "CMS",
            "pattern": r"ghost-head|ghost-foot|ghost-content-api",
        },
        "Next.js": {
            "category": "Framework",
            "pattern": r"__NEXT_DATA__|_next/static|_next/image",
        },
        "Nuxt.js": {
            "category": "Framework",
            "pattern": r"__NUXT__|/_nuxt/",
        },
        "Laravel": {
            "category": "Framework",
            "pattern": r'laravel_session|csrf-token',
        },
        "Django": {
            "category": "Framework",
            "pattern": r'csrfmiddlewaretoken|__admin_media_prefix__',
        },
        "Flask": {
            "category": "Framework",
            "pattern": r'flask|Werkzeug',
        },
        "Express": {
            "category": "Framework",
            "pattern": r'express',
        },
        "ASP.NET": {
            "category":
            "Framework",
            "pattern":
            r'__VIEWSTATE|__EVENTVALIDATION|WebResource\.axd|ScriptResource\.axd',
        },
    },
    "Script": {
        "WordPress": {
            "category": "CMS",
            "pattern": r"/wp-content/|/wp-includes/",
        },
        "WooCommerce": {
            "category": "Plugin",
            "pattern": r"woocommerce",
        },
        "Elementor": {
            "category": "Plugin",
            "pattern": r"elementor",
        },
        "Joomla": {
            "category": "CMS",
            "pattern": r"/media/system/js/",
        },
        "Drupal": {
            "category": "CMS",
            "pattern": r"/sites/default/files/js/|drupal.js",
        },
        "Magento": {
            "category": "CMS",
            "pattern": r"/static/version|Magento_",
        },
        "Shopify": {
            "category": "CMS",
            "pattern": r"cdn.shopify.com|shopify",
        },
        "Wix": {
            "category": "CMS",
            "pattern": r"wixstatic.com",
        },
        "Ghost": {
            "category": "CMS",
            "pattern": r"ghost-sdk|ghost",
        },
        "Next.js": {
            "category": "Framework",
            "pattern": r"/_next/static/",
        },
        "Nuxt.js": {
            "category": "Framework",
            "pattern": r"/_nuxt/",
        },
        "React": {
            "category": "Framework",
            "pattern": r"react(\.min)?\.js|react-dom",
        },
        "Vue.js": {
            "category": "Framework",
            "pattern": r"vue(\.runtime)?(\.min)?\.js",
        },
        "Angular": {
            "category": "Framework",
            "pattern": r"angular(\.min)?\.js|zone\.js",
        },
        "Svelte": {
            "category": "Framework",
            "pattern": r"svelte",
        },
        "Ember.js": {
            "category": "Framework",
            "pattern": r"ember(\.min)?\.js",
        },
        "Backbone.js": {
            "category": "Framework",
            "pattern": r"backbone(\.min)?\.js",
        },
        "Alpine.js": {
            "category": "Framework",
            "pattern": r"alpine(\.min)?\.js",
        },
        "Preact": {
            "category": "Framework",
            "pattern": r"preact(\.min)?\.js",
        },
    },
    "Cookie": {
        "WordPress": {
            "category": "CMS",
            "pattern": r"wordpress_|wp-settings-|wp-postpass_",
        },
        "WooCommerce": {
            "category":
            "Plugin",
            "pattern":
            r"woocommerce_|woocommerce_items_in_cart|wp_woocommerce_session_",
        },
        "Joomla": {
            "category": "CMS",
            "pattern": r"[a-f0-9]{32}",
        },
        "Drupal": {
            "category": "CMS",
            "pattern": r"SESS[a-zA-Z0-9]+",
        },
        "Magento": {
            "category": "CMS",
            "pattern": r"PHPSESSID|form_key|mage-cache",
        },
        "Shopify": {
            "category": "CMS",
            "pattern": r"_shopify|cart_sig|cart_currency|secure_customer_sig",
        },
        "Ghost": {
            "category": "CMS",
            "pattern": r"ghost-admin-api-session",
        },
        "Laravel": {
            "category": "Framework",
            "pattern": r"laravel_session|XSRF-TOKEN",
        },
        "Django": {
            "category": "Framework",
            "pattern": r"csrftoken|sessionid",
        },
        "Flask": {
            "category": "Framework",
            "pattern": r"session=",
        },
        "Express": {
            "category": "Framework",
            "pattern": r"connect.sid",
        },
        "ASP.NET": {
            "category": "Framework",
            "pattern": r"ASP\.NET_SessionId|__RequestVerificationToken",
        },
        "NextAuth": {
            "category": "Authentication",
            "pattern": r"next-auth",
        },
        "Supabase": {
            "category": "Backend",
            "pattern": r"sb-[a-z0-9]+-auth-token",
        },
        "Firebase": {
            "category": "Backend",
            "pattern": r"firebase",
        },
        "Auth0": {
            "category": "Authentication",
            "pattern": r"auth0",
        },
        "Keycloak": {
            "category": "Authentication",
            "pattern": r"KEYCLOAK_",
        },
        "Cloudflare": {
            "category": "CDN",
            "pattern": r"__cf_bm|cf_clearance|__cflb",
        },
    },
    "Header": {
        "WordPress": {
            "category": "CMS",
            "header": "Link",
            "pattern": r"/wp-json/?",
        },
        "WordPress REST API": {
            "category": "CMS",
            "header": "X-Pingback",
            "pattern": r".+",
        },
        "Drupal": {
            "category": "CMS",
            "header": "X-Generator",
            "pattern": r"Drupal",
        },
        "Laravel": {
            "category": "Framework",
            "header": "Set-Cookie",
            "pattern": r"laravel_session",
        },
        "Django": {
            "category": "Framework",
            "header": "Set-Cookie",
            "pattern": r"csrftoken|sessionid",
        },
        "Flask": {
            "category": "Framework",
            "header": "Server",
            "pattern": r"Werkzeug",
        },
        "Express": {
            "category": "Framework",
            "header": "X-Powered-By",
            "pattern": r"Express",
        },
        "ASP.NET": {
            "category": "Framework",
            "header": "X-Powered-By",
            "pattern": r"ASP\.NET",
        },
        "Next.js": {
            "category": "Framework",
            "header": "X-Powered-By",
            "pattern": r"Next\.js",
        },
        "Nuxt.js": {
            "category": "Framework",
            "header": "X-Powered-By",
            "pattern": r"Nuxt",
        },
        "Ghost": {
            "category": "CMS",
            "header": "X-Ghost-Cache",
            "pattern": r".+",
        },
        "Shopify": {
            "category": "CMS",
            "header": "X-ShopId",
            "pattern": r".+",
        },
    },
}

# ==========================================================
# Cookie Prefix Signatures — matched against the start of any
# cookie name (some services generate dynamic cookie suffixes).
# Categories: WAF, CDN, Ads
# ==========================================================

COOKIE_PREFIX_SIGNATURES = [
    ("BIGipServer", "F5 BIG-IP", "WAF"),
    ("incap_ses_", "Imperva Incapsula", "WAF"),
    ("visid_incap_", "Imperva Incapsula", "WAF"),
    ("__cfruid", "Cloudflare", "CDN"),
    ("_gcl_", "Google Ads", "Ads"),
    ("_fbp", "Meta Pixel", "Ads"),
]

# ==========================================================
# HTML Signatures (substring match against raw HTML)
# Categories: CMS, Frontend Framework, Backend
# ==========================================================

HTML_SIGNATURES = {
    "WordPress": {
        "category": "CMS",
        "patterns": [
            "wp-content",
            "wp-includes",
            "wp-json",
        ],
    },
    "Drupal": {
        "category": "CMS",
        "patterns": [
            "/sites/default/",
            "Drupal.settings",
        ],
    },
    "Joomla": {
        "category": "CMS",
        "patterns": [
            "joomla",
            "/media/system/",
        ],
    },
    "Wix": {
        "category": "CMS",
        "patterns": [
            "wixstatic.com",
            "wix.com",
        ],
    },
    "Squarespace": {
        "category": "CMS",
        "patterns": [
            "squarespace.com",
            "static1.squarespace.com",
        ],
    },
    "Shopify": {
        "category": "CMS",
        "patterns": [
            "cdn.shopify.com",
            "Shopify.theme",
        ],
    },
    "Magento": {
        "category": "CMS",
        "patterns": [
            "Mage.Cookies",
            "/skin/frontend/",
        ],
    },
    "Ghost": {
        "category": "CMS",
        "patterns": [
            "content=\"Ghost",
            "ghost-url",
        ],
    },
    "TYPO3": {
        "category": "CMS",
        "patterns": [
            "typo3conf",
            "typo3temp",
        ],
    },
    "Webflow": {
        "category": "CMS",
        "patterns": [
            "webflow.com",
            "data-wf-page",
        ],
    },
    "PrestaShop": {
        "category": "CMS",
        "patterns": [
            "prestashop",
        ],
    },
    "OpenCart": {
        "category": "CMS",
        "patterns": [
            "catalog/view/theme",
            "route=product",
        ],
    },
    "Blogger": {
        "category":
        "CMS",
        "patterns": [
            "blogger.googleusercontent.com",
            "blogger.com/static",
            "data:blog",
            "expr:widget",
            "b:section",
            "b:widget",
        ],
    },
    "Laravel": {
        "category": "Backend",
        "patterns": [
            "csrf-token",
            "laravel",
        ],
    },
    "Django": {
        "category": "Backend",
        "patterns": [
            "csrfmiddlewaretoken",
            "__admin_media_prefix__",
        ],
    },
    "Ruby on Rails": {
        "category": "Backend",
        "patterns": [
            "csrf-param",
            "authenticity_token",
        ],
    },
    "Symfony": {
        "category": "Backend",
        "patterns": [
            "symfony",
        ],
    },
    "CodeIgniter": {
        "category": "Backend",
        "patterns": [
            "codeigniter",
        ],
    },
    "ASP.NET": {
        "category": "Backend",
        "patterns": [
            "__VIEWSTATE",
            "__EVENTVALIDATION",
        ],
    },
    "React": {
        "category": "Frontend Framework",
        "patterns": [
            "react",
            "__REACT_DEVTOOLS",
        ],
    },
    "Next.js": {
        "category": "Frontend Framework",
        "patterns": [
            "__NEXT_DATA__",
            "_next/static",
        ],
    },
    "Nuxt.js": {
        "category": "Frontend Framework",
        "patterns": [
            "__NUXT__",
            "_nuxt/",
        ],
    },
    "Vue.js": {
        "category": "Frontend Framework",
        "patterns": [
            "__vue__",
            "vue.js",
        ],
    },
    "Angular": {
        "category": "Frontend Framework",
        "patterns": [
            "ng-version",
            "ng-app",
        ],
    },
    "Svelte": {
        "category": "Frontend Framework",
        "patterns": [
            "svelte-",
        ],
    },
    "Gatsby": {
        "category": "Frontend Framework",
        "patterns": [
            "___gatsby",
        ],
    },
    "Ember.js": {
        "category": "Frontend Framework",
        "patterns": [
            "ember-view",
            "data-ember-action",
        ],
    },
    "Alpine.js": {
        "category": "Frontend Framework",
        "patterns": [
            "x-data=",
        ],
    },
}

# ==========================================================
# Cookie Signatures (exact cookie name match)
# Categories: Backend, CMS, Analytics, CDN
# ==========================================================

COOKIE_SIGNATURES = {
    "PHPSESSID": ("PHP", "Backend"),
    "JSESSIONID": ("Java", "Backend"),
    "ASP.NET_SessionId": ("ASP.NET", "Backend"),
    "laravel_session": ("Laravel", "Backend"),
    "django_language": ("Django", "Backend"),
    "csrftoken": ("Django", "Backend"),
    "wordpress_logged_in": ("WordPress", "CMS"),
    "wp-settings-time": ("WordPress", "CMS"),
    "XSRF-TOKEN": ("Laravel", "Backend"),
    "_ga": ("Google Analytics", "Analytics"),
    "_gid": ("Google Analytics", "Analytics"),
    "_hjSessionUser": ("Hotjar", "Analytics"),
    "mp_mixpanel": ("Mixpanel", "Analytics"),
    "__cf_bm": ("Cloudflare", "CDN"),
    "__cfduid": ("Cloudflare", "CDN"),
}

# ==========================================================
# Script Signatures (substring match against <script src>)
# Categories: JS Library, CSS Framework, Analytics,
# Tag Manager, Ads, Payment, Security
# ==========================================================

SCRIPT_SIGNATURES = {

    # --- JS Libraries ---
    "jquery": ("jQuery", "JS Library"),
    "lodash": ("Lodash", "JS Library"),
    "underscore": ("Underscore.js", "JS Library"),
    "moment.js": ("Moment.js", "JS Library"),
    "moment.min.js": ("Moment.js", "JS Library"),
    "axios": ("Axios", "JS Library"),
    "d3.min.js": ("D3.js", "JS Library"),
    "d3.v": ("D3.js", "JS Library"),
    "chart.js": ("Chart.js", "JS Library"),
    "three.min.js": ("Three.js", "JS Library"),
    "gsap": ("GSAP", "JS Library"),
    "swiper": ("Swiper.js", "JS Library"),
    "htmx": ("htmx", "JS Library"),
    "backbone": ("Backbone.js", "JS Library"),
    "knockout": ("Knockout.js", "JS Library"),
    "popper": ("Popper.js", "JS Library"),
    "prototype.js": ("Prototype.js", "JS Library"),
    "modernizr": ("Modernizr", "JS Library"),

    # --- Frontend Frameworks (also detectable via script) ---
    "react": ("React", "Frontend Framework"),
    "_next": ("Next.js", "Frontend Framework"),
    "vue": ("Vue.js", "Frontend Framework"),
    "angular": ("Angular", "Frontend Framework"),
    "alpine": ("Alpine.js", "Frontend Framework"),
    "ember": ("Ember.js", "Frontend Framework"),

    # --- CSS Frameworks ---
    "bootstrap": ("Bootstrap", "CSS Framework"),
    "tailwind": ("Tailwind CSS", "CSS Framework"),
    "bulma": ("Bulma", "CSS Framework"),
    "foundation.min.js": ("Foundation", "CSS Framework"),
    "materialize": ("Materialize CSS", "CSS Framework"),
    "semantic.min": ("Semantic UI", "CSS Framework"),
    "fontawesome": ("Font Awesome", "CSS Framework"),
    "font-awesome": ("Font Awesome", "CSS Framework"),

    # --- Analytics ---
    "analytics.js": ("Google Analytics", "Analytics"),
    "gtag": ("Google Analytics", "Analytics"),
    "matomo": ("Matomo", "Analytics"),
    "hotjar": ("Hotjar", "Analytics"),
    "mixpanel": ("Mixpanel", "Analytics"),
    "clarity.ms": ("Microsoft Clarity", "Analytics"),
    "amplitude": ("Amplitude", "Analytics"),
    "fullstory": ("FullStory", "Analytics"),
    "heap": ("Heap Analytics", "Analytics"),
    "plausible.io": ("Plausible Analytics", "Analytics"),
    "cloudflareinsights.com": ("Cloudflare Web Analytics", "Analytics"),

    # --- Tag Managers ---
    "googletagmanager.com": ("Google Tag Manager", "Tag Manager"),
    "tealium": ("Tealium", "Tag Manager"),
    "adobedtm.com": ("Adobe Experience Platform Launch", "Tag Manager"),

    # --- Ads ---
    "googlesyndication.com": ("Google AdSense", "Ads"),
    "doubleclick.net": ("Google DoubleClick", "Ads"),
    "adsbygoogle": ("Google AdSense", "Ads"),
    "amazon-adsystem.com": ("Amazon Ads", "Ads"),
    "media.net": ("Media.net", "Ads"),
    "taboola": ("Taboola", "Ads"),
    "outbrain": ("Outbrain", "Ads"),
    "criteo": ("Criteo", "Ads"),

    # --- Payment ---
    "js.stripe.com": ("Stripe", "Payment"),
    "paypalobjects.com": ("PayPal", "Payment"),
    "paypal.com/sdk": ("PayPal", "Payment"),
    "checkout.razorpay.com": ("Razorpay", "Payment"),
    "js.braintreegateway.com": ("Braintree", "Payment"),
    "js.squareup.com": ("Square", "Payment"),
    "cashfree.com": ("Cashfree", "Payment"),
    "payu.in": ("PayU", "Payment"),
    "instamojo.com": ("Instamojo", "Payment"),
    "billdesk.com": ("BillDesk", "Payment"),
    "ccavenue.com": ("CCAvenue", "Payment"),
    "securegw-stage.paytm.in": ("Paytm", "Payment"),
    "securegw.paytm.in": ("Paytm", "Payment"),

    # --- Security ---
    "recaptcha": ("Google reCAPTCHA", "Security"),
    "hcaptcha.com": ("hCaptcha", "Security"),
    "challenges.cloudflare.com/turnstile":
    ("Cloudflare Turnstile", "Security"),
    "cookielaw.org": ("OneTrust", "Security"),
    "onetrust": ("OneTrust", "Security"),
}

# ==========================================================
# Link Signatures (substring match against <link href>)
# Categories: Fonts, CDN, CSS Framework
# ==========================================================

LINK_SIGNATURES = {
    "fonts.googleapis.com": ("Google Fonts", "Fonts"),
    "fonts.gstatic.com": ("Google Fonts", "Fonts"),
    "use.typekit.net": ("Adobe Fonts (Typekit)", "Fonts"),
    "fonts.adobe.com": ("Adobe Fonts", "Fonts"),
    "fast.fonts.net": ("Fonts.com (Monotype)", "Fonts"),
    "cloud.typography.com": ("Hoefler&Co", "Fonts"),
    "use.fontawesome.com": ("Font Awesome", "Fonts"),
    "cdnjs.cloudflare.com": ("cdnjs (Cloudflare)", "CDN"),
    "cdn.jsdelivr.net": ("jsDelivr", "CDN"),
    "unpkg.com": ("unpkg", "CDN"),
    "bootstrap": ("Bootstrap", "CSS Framework"),
    "bulma": ("Bulma", "CSS Framework"),
    "materialize": ("Materialize CSS", "CSS Framework"),
}

# ==========================================================
# Inline JavaScript Signatures
# ==========================================================

INLINE_JS_SIGNATURES = {

    # Analytics
    "gtag(": ("Google Analytics GA4", "Analytics"),
    "ga(": ("Google Analytics Universal", "Analytics"),
    "dataLayer": ("Google Tag Manager", "Tag Manager"),
    "gtm.start": ("Google Tag Manager", "Tag Manager"),

    # Ads
    "adsbygoogle": ("Google AdSense", "Advertising"),
    "googletag.pubads": ("Google Publisher Tags", "Advertising"),

    # Facebook
    "FB.init": ("Facebook Login", "Authentication"),
    "facebook-jssdk": ("Facebook SDK", "Authentication"),

    # Security
    "grecaptcha": ("Google reCAPTCHA", "Security"),
    "hcaptcha": ("hCaptcha", "Security"),

    # Payment
    "Stripe(": ("Stripe", "Payment"),
    "paypal.Buttons": ("PayPal", "Payment"),
    "Razorpay(": ("Razorpay", "Payment"),

    # Analytics
    "mixpanel.init": ("Mixpanel", "Analytics"),
    "hj(": ("Hotjar", "Analytics"),
    "clarity(": ("Microsoft Clarity", "Analytics"),

    # Video
    "YT.Player": ("YouTube", "Video Player"),
}

# ==========================================================
# DOM Attribute Signatures
# ==========================================================

DOM_ATTRIBUTE_SIGNATURES = {
    "ng-app": ("Angular", "Frontend Framework"),
    "ng-version": ("Angular", "Frontend Framework"),
    "x-data": ("Alpine.js", "Frontend Framework"),
    "x-show": ("Alpine.js", "Frontend Framework"),
    "wire:id": ("Livewire", "Frontend Framework"),
    "wire:model": ("Livewire", "Frontend Framework"),
    "hx-get": ("HTMX", "Frontend Framework"),
    "hx-post": ("HTMX", "Frontend Framework"),
    "data-bs-toggle": ("Bootstrap", "CSS Framework"),
    "data-toggle": ("Bootstrap", "CSS Framework"),
    "data-aos": ("AOS", "JS Library"),
    "data-fancybox": ("FancyBox", "JS Library"),
}

# ==========================================================
# URL Signatures
# ==========================================================

URL_SIGNATURES = {

    # Google
    "googleapis.com": ("Google APIs", "Services"),
    "gstatic.com": ("Google", "Services"),
    "google.com/maps": ("Google Maps", "Services"),
    "maps.googleapis.com": ("Google Maps", "Services"),
    "fonts.googleapis.com": ("Google Fonts", "Fonts"),

    # YouTube / Video
    "youtube.com": ("YouTube", "Video Player"),
    "youtu.be": ("YouTube", "Video Player"),
    "youtube-nocookie.com": ("YouTube", "Video Player"),
    "player.vimeo.com": ("Vimeo", "Video Player"),

    # Facebook
    "facebook.net": ("Facebook SDK", "Authentication"),
    "connect.facebook.net": ("Facebook SDK", "Authentication"),
    "facebook.com": ("Facebook", "Social"),

    # CDN
    "cdnjs.cloudflare.com": ("cdnjs", "CDN"),
    "cdn.jsdelivr.net": ("jsDelivr", "CDN"),
    "unpkg.com": ("unpkg", "CDN"),

    # CMS
    "cdn.shopify.com": ("Shopify", "CMS"),
    "wixstatic.com": ("Wix", "CMS"),

    # Payments
    "js.stripe.com": ("Stripe", "Payment"),
    "checkout.razorpay.com": ("Razorpay", "Payment"),
    "paypal.com": ("PayPal", "Payment"),

    # Security
    "recaptcha": ("Google reCAPTCHA", "Security"),
    "hcaptcha.com": ("hCaptcha", "Security"),
}

# ==========================================================
# Technology Version Patterns
# ==========================================================

TECH_VERSION_PATTERNS = {
    "jQuery": [
        r"jquery[-.]([\d.]+)",
        r"jquery\.min\.js\?v=([\d.]+)",
    ],
    "Bootstrap": [
        r"bootstrap[-.]([\d.]+)",
        r"bootstrap@([\d.]+)",
    ],
    "Font Awesome": [
        r"fontawesome[-.]([\d.]+)",
        r"font-awesome[-.]([\d.]+)",
    ],
    "Swiper.js": [
        r"swiper[-.]([\d.]+)",
    ],
    "OWL Carousel": [
        r"owl(?:\.|-)carousel[-.]([\d.]+)",
    ],
}

FORM_SIGNATURES = {
    "__VIEWSTATE": ("ASP.NET", "Backend"),
    "__EVENTVALIDATION": ("ASP.NET", "Backend"),
    "csrfmiddlewaretoken": ("Django", "Backend"),
    "authenticity_token": ("Ruby on Rails", "Backend"),
    "_token": ("Laravel", "Backend"),
    "g-recaptcha-response": ("Google reCAPTCHA", "Security"),
    "h-captcha-response": ("hCaptcha", "Security"),
    "cf-turnstile-response": ("Cloudflare Turnstile", "Security"),
}

# ==========================================================
# Operating System Signatures
# ==========================================================

OS_SIGNATURES = {
    "Ubuntu": {
        "category": "Operating System",
        "headers": [
            "ubuntu",
        ],
        "html": [
            "apache2 ubuntu default page",
            "ubuntu logo",
        ],
    },
    "Debian": {
        "category": "Operating System",
        "headers": [
            "debian",
        ],
        "html": [],
    },
    "CentOS": {
        "category": "Operating System",
        "headers": [
            "centos",
        ],
        "html": [],
    },
    "Rocky Linux": {
        "category": "Operating System",
        "headers": [
            "rocky",
        ],
        "html": [],
    },
    "AlmaLinux": {
        "category": "Operating System",
        "headers": [
            "alma",
        ],
        "html": [],
    },
    "Fedora": {
        "category": "Operating System",
        "headers": [
            "fedora",
        ],
        "html": [],
    },
    "Alpine Linux": {
        "category": "Operating System",
        "headers": [
            "alpine",
        ],
        "html": [],
    },
    "FreeBSD": {
        "category": "Operating System",
        "headers": [
            "freebsd",
        ],
        "html": [],
    },
    "OpenBSD": {
        "category": "Operating System",
        "headers": [
            "openbsd",
        ],
        "html": [],
    },
    "Windows Server": {
        "category": "Operating System",
        "headers": [
            "microsoft-iis",
            "asp.net",
            "win64",
            "windows",
        ],
        "html": [],
    },
}

# ==========================================================
# EXTRA SIGNATURES
# ==========================================================

# ---------- Runtimes / Web servers / Hosting (Server header) ----------
EXTRA_HEADER_SIGNATURES = {
    "Server": {
        "Node.js": {
            "category": "Backend",
            "pattern": r"Node\.js/?([\d\.]+)?",
        },
        "Deno": {
            "category": "Backend",
            "pattern": r"Deno/?([\d\.]+)?",
        },
        "Bun": {
            "category": "Backend",
            "pattern": r"\bBun\b",
        },
        "Puma": {
            "category": "Web Server",
            "pattern": r"Puma/?([\d\.]+)?",
        },
        "Unicorn": {
            "category": "Web Server",
            "pattern": r"[Uu]nicorn/?([\d\.]+)?",
        },
        "Phusion Passenger": {
            "category": "Backend",
            "pattern": r"Phusion[_ ]Passenger/?([\d\.]+)?",
        },
        "GitHub.com": {
            "category": "Hosting",
            "pattern": r"GitHub\.com",
        },
        "Vercel": {
            "category": "Hosting",
            "pattern": r"Vercel",
        },
        "Netlify": {
            "category": "Hosting",
            "pattern": r"Netlify",
        },
    },
    "X-Powered-By": {
        "Fastify": {
            "category": "Backend",
            "pattern": r"Fastify",
        },
        "NestJS": {
            "category": "Backend",
            "pattern": r"NestJS",
        },
        "Umbraco": {
            "category": "CMS",
            "pattern": r"Umbraco",
        },
        "AWS Lambda": {
            "category": "Backend",
            "pattern": r"AWS Lambda",
        },
    },
}

# ---------- Presence-only headers: caching, security, tracing, WAF ----------
EXTRA_PRESENCE_HEADER_SIGNATURES = {
    "X-Drupal-Cache": ("Drupal", "CMS"),
    "X-Drupal-Dynamic-Cache": ("Drupal", "CMS"),
    "X-Varnish": ("Varnish", "Reverse Proxy"),
    "X-Litespeed-Cache": ("LiteSpeed Cache", "Caching"),
    "X-Turbo-Charged-By": ("LiteSpeed", "Web Server"),
    "X-Pantheon-Styx-Hostname": ("Pantheon", "Hosting"),
    "X-Wix-Request-Id": ("Wix", "CMS"),
    "X-ShopId": ("Shopify", "CMS"),
    "X-Shopify-Stage": ("Shopify", "CMS"),
    "X-Kinsta-Cache": ("Kinsta", "Hosting"),
    "X-Cacheable": ("WP Engine", "Hosting"),
    "X-Redirect-By": ("WordPress", "CMS"),
    "X-Pingback": ("WordPress", "CMS"),
    "X-Content-Type-Options": ("X-Content-Type-Options", "Security"),
    "X-XSS-Protection": ("X-XSS-Protection", "Security"),
    "Referrer-Policy": ("Referrer-Policy", "Security"),
    "Cross-Origin-Opener-Policy": ("Cross-Origin-Opener-Policy", "Security"),
    "Cross-Origin-Resource-Policy":
    ("Cross-Origin-Resource-Policy", "Security"),
    "Cross-Origin-Embedder-Policy":
    ("Cross-Origin-Embedder-Policy", "Security"),
    "Expect-CT": ("Expect-CT", "Security"),
    "NEL": ("Network Error Logging", "Security"),
    "Report-To": ("Reporting API", "Security"),
    "Server-Timing": ("Server-Timing API", "Observability"),
    "X-B3-TraceId": ("Zipkin / B3 Tracing", "Observability"),
    "traceparent": ("W3C Trace Context", "Observability"),
    "X-Datadome": ("DataDome", "WAF"),
    "X-Distil-Cs": ("Distil Networks (Imperva)", "WAF"),
    "X-SigSci-Tags": ("Signal Sciences", "WAF"),
    "X-Amz-Cf-Pop": ("Amazon CloudFront", "CDN"),
    "X-Now-Trace": ("Vercel", "Hosting"),
}

# ---------- Reverse proxies / API gateways ----------
EXTRA_REVERSE_PROXY_SIGNATURES = {
    "Server": {
        "Kong": {
            "category": "Reverse Proxy",
            "pattern": r"kong/?([\d\.]+)?",
        },
        "Tyk": {
            "category": "Reverse Proxy",
            "pattern": r"tyk",
        },
        "Zuul": {
            "category": "Reverse Proxy",
            "pattern": r"zuul",
        },
        "Apache APISIX": {
            "category": "Reverse Proxy",
            "pattern": r"APISIX",
        },
        "Pomerium": {
            "category": "Reverse Proxy",
            "pattern": r"pomerium",
        },
    },
}

# ---------- CDN providers ----------
EXTRA_CDN_SIGNATURES = {
    "Server": {
        "BunnyCDN": {
            "category": "CDN",
            "pattern": r"bunnycdn",
        },
        "KeyCDN": {
            "category": "CDN",
            "pattern": r"keycdn",
        },
        "StackPath": {
            "category": "CDN",
            "pattern": r"stackpath",
        },
        "G-Core": {
            "category": "CDN",
            "pattern": r"gcorelabs|g-core",
        },
        "CacheFly": {
            "category": "CDN",
            "pattern": r"cachefly",
        },
        "Tencent Cloud CDN": {
            "category": "CDN",
            "pattern": r"tencent",
        },
        "Alibaba Cloud CDN": {
            "category": "CDN",
            "pattern": r"alicloud|alikunlun",
        },
    },
    "X-Edge-Location": {
        "Generic Edge CDN": {
            "category": "CDN",
            "pattern": r".+",
        },
    },
}

# ---------- WAF vendors ----------
EXTRA_WAF_SIGNATURES = {
    "Server": {
        "Radware": {
            "category": "WAF",
            "pattern": r"radware",
        },
        "Reblaze": {
            "category": "WAF",
            "pattern": r"reblaze",
        },
        "Wallarm": {
            "category": "WAF",
            "pattern": r"wallarm",
        },
    },
}

# ---------- CMS / static-site-generator meta generators ----------
EXTRA_CMS_META_GENERATOR = {
    "Squarespace": {
        "category": "CMS",
        "pattern": r"squarespace"
    },
    "Webflow": {
        "category": "CMS",
        "pattern": r"webflow"
    },
    "TYPO3": {
        "category": "CMS",
        "pattern": r"typo3"
    },
    "Hugo": {
        "category": "Static Site Generator",
        "pattern": r"hugo\s*([0-9.]+)?"
    },
    "Jekyll": {
        "category": "Static Site Generator",
        "pattern": r"jekyll\s*([0-9.]+)?"
    },
    "Gatsby": {
        "category": "Static Site Generator",
        "pattern": r"gatsby"
    },
    "Eleventy": {
        "category": "Static Site Generator",
        "pattern": r"eleventy|11ty"
    },
    "PrestaShop": {
        "category": "CMS",
        "pattern": r"prestashop\s*([0-9.]+)?"
    },
    "OpenCart": {
        "category": "CMS",
        "pattern": r"opencart\s*([0-9.]+)?"
    },
    "BigCommerce": {
        "category": "CMS",
        "pattern": r"bigcommerce"
    },
    "Craft CMS": {
        "category": "CMS",
        "pattern": r"craft\s*cms\s*([0-9.]+)?"
    },
    "Kirby": {
        "category": "CMS",
        "pattern": r"kirby\s*([0-9.]+)?"
    },
    "concrete5": {
        "category": "CMS",
        "pattern": r"concrete5|concretecms\s*([0-9.]+)?"
    },
    "Umbraco": {
        "category": "CMS",
        "pattern": r"umbraco\s*([0-9.]+)?"
    },
    "SharePoint": {
        "category": "CMS",
        "pattern": r"sharepoint\s*([0-9.]+)?"
    },
    "Wagtail": {
        "category": "CMS",
        "pattern": r"wagtail\s*([0-9.]+)?"
    },
    "Statamic": {
        "category": "CMS",
        "pattern": r"statamic\s*([0-9.]+)?"
    },
}

# ---------- SaaS widgets, headless CMS, observability, build tools ----------
EXTRA_HTML_SIGNATURES = {
    "Sentry": {
        "category": "Error Tracking",
        "patterns": ["sentry.io", "sentry-trace"]
    },
    "New Relic": {
        "category": "Observability",
        "patterns": ["newrelic.com", "nr-data.net"]
    },
    "Segment": {
        "category": "Analytics",
        "patterns": ["cdn.segment.com", "segment.io"]
    },
    "HubSpot": {
        "category": "Marketing",
        "patterns": ["hs-scripts.com", "hsforms.net"]
    },
    "Intercom": {
        "category": "Customer Support",
        "patterns": ["widget.intercom.io", "intercomcdn.com"]
    },
    "Zendesk": {
        "category": "Customer Support",
        "patterns": ["zdassets.com", "zendesk.com"]
    },
    "Crisp": {
        "category": "Customer Support",
        "patterns": ["client.crisp.chat"]
    },
    "Tawk.to": {
        "category": "Customer Support",
        "patterns": ["embed.tawk.to"]
    },
    "Drift": {
        "category": "Customer Support",
        "patterns": ["js.driftt.com"]
    },
    "Freshchat": {
        "category": "Customer Support",
        "patterns": ["wchat.freshchat.com"]
    },
    "LiveChat": {
        "category": "Customer Support",
        "patterns": ["cdn.livechatinc.com"]
    },
    "Optimizely": {
        "category": "A/B Testing",
        "patterns": ["cdn.optimizely.com"]
    },
    "VWO": {
        "category": "A/B Testing",
        "patterns": ["dev.visualwebsiteoptimizer.com"]
    },
    "Google Optimize": {
        "category": "A/B Testing",
        "patterns": ["googleoptimize.com"]
    },
    "Cloudinary": {
        "category": "Media/CDN",
        "patterns": ["res.cloudinary.com"]
    },
    "imgix": {
        "category": "Media/CDN",
        "patterns": [".imgix.net"]
    },
    "Contentful": {
        "category": "Headless CMS",
        "patterns": ["cdn.contentful.com", "images.ctfassets.net"]
    },
    "Sanity": {
        "category": "Headless CMS",
        "patterns": ["cdn.sanity.io"]
    },
    "Strapi": {
        "category": "Headless CMS",
        "patterns": ["strapi.io"]
    },
    "Prismic": {
        "category": "Headless CMS",
        "patterns": ["prismic.io"]
    },
    "Storyblok": {
        "category": "Headless CMS",
        "patterns": ["storyblok.com"]
    },
    "Apollo Client": {
        "category": "API",
        "patterns": ["apollo-client", "__APOLLO_STATE__"]
    },
    "Webpack": {
        "category": "Build Tool",
        "patterns": ["webpackjsonp", "__webpack_require__"]
    },
    "Vite": {
        "category": "Build Tool",
        "patterns": ["/@vite/client"]
    },
    "Parcel": {
        "category": "Build Tool",
        "patterns": ["parcelrequire"]
    },
    "Redux": {
        "category": "State Management",
        "patterns": ["__REDUX_DEVTOOLS_EXTENSION__"]
    },
    "Firebase": {
        "category": "Backend",
        "patterns": ["firebaseio.com", "firebaseapp.com"]
    },
    "Supabase": {
        "category": "Backend",
        "patterns": ["supabase.co", "supabase.in"]
    },
    "Google reCAPTCHA v3": {
        "category": "Security",
        "patterns": ["recaptcha/api.js?render="]
    },
    "Algolia Search": {
        "category": "Search",
        "patterns": ["algolia.net", "algolianet.com"]
    },
}

EXTRA_SCRIPT_SIGNATURES = {
    "sentry.io": ("Sentry", "Error Tracking"),
    "browser.sentry-cdn.com": ("Sentry", "Error Tracking"),
    "js-agent.newrelic.com": ("New Relic", "Observability"),
    "cdn.segment.com": ("Segment", "Analytics"),
    "js.hs-scripts.com": ("HubSpot", "Marketing"),
    "widget.intercom.io": ("Intercom", "Customer Support"),
    "static.zdassets.com": ("Zendesk", "Customer Support"),
    "client.crisp.chat": ("Crisp", "Customer Support"),
    "embed.tawk.to": ("Tawk.to", "Customer Support"),
    "js.driftt.com": ("Drift", "Customer Support"),
    "wchat.freshchat.com": ("Freshchat", "Customer Support"),
    "cdn.optimizely.com": ("Optimizely", "A/B Testing"),
    "visualwebsiteoptimizer.com": ("VWO", "A/B Testing"),
    "googleoptimize.com": ("Google Optimize", "A/B Testing"),
    "polyfill.io": ("Polyfill.io", "JS Library"),
    "apollo-client": ("Apollo Client", "API"),
    "graphql-request": ("GraphQL", "API"),
    "workbox": ("Workbox (PWA)", "Frontend Framework"),
    "algolia": ("Algolia Search", "Search"),
    "typesense": ("Typesense Search", "Search"),
    "meilisearch": ("MeiliSearch", "Search"),
}

EXTRA_LINK_SIGNATURES = {
    "res.cloudinary.com": ("Cloudinary", "Media/CDN"),
    "imgix.net": ("imgix", "Media/CDN"),
    "images.ctfassets.net": ("Contentful", "Headless CMS"),
    "cdn.sanity.io": ("Sanity", "Headless CMS"),
    "kit.fontawesome.com": ("Font Awesome", "Fonts"),
    "fonts.bunny.net": ("Bunny Fonts", "Fonts"),
}

EXTRA_COOKIE_SIGNATURES = {
    "__Secure-next-auth.session-token": ("NextAuth", "Authentication"),
    "PLAY_SESSION": ("Play Framework", "Backend"),
    "symfony": ("Symfony", "Backend"),
    "ci_session": ("CodeIgniter", "Backend"),
    "sails.sid": ("Sails.js", "Backend"),
    "koa.sess": ("Koa.js", "Backend"),
    "_shopify_y": ("Shopify", "CMS"),
    "wixLanguage": ("Wix", "CMS"),
    "OptanonConsent": ("OneTrust", "Security"),
}

EXTRA_COOKIE_PREFIX_SIGNATURES = [
    ("__Secure-", "Secure Cookie Prefix", "Security"),
    ("__Host-", "Host Cookie Prefix", "Security"),
    ("AWSALB", "AWS Application Load Balancer", "Hosting"),
    ("AWSALBCORS", "AWS Application Load Balancer", "Hosting"),
    ("__stripe_", "Stripe", "Payment"),
    ("razorpay", "Razorpay", "Payment"),
    ("_hjid", "Hotjar", "Analytics"),
    ("amplitude_id", "Amplitude", "Analytics"),
]

EXTRA_INLINE_JS_SIGNATURES = {
    "Sentry.init": ("Sentry", "Error Tracking"),
    "newrelic.config": ("New Relic", "Observability"),
    "analytics.load": ("Segment", "Analytics"),
    "zE(": ("Zendesk", "Customer Support"),
    "$crisp": ("Crisp", "Customer Support"),
    "Tawk_API": ("Tawk.to", "Customer Support"),
    "drift.load": ("Drift", "Customer Support"),
    "__APOLLO_STATE__": ("Apollo Client", "API"),
    "webpackJsonp": ("Webpack", "Build Tool"),
}

EXTRA_DOM_ATTRIBUTE_SIGNATURES = {
    "v-bind": ("Vue.js", "Frontend Framework"),
    "v-if": ("Vue.js", "Frontend Framework"),
    "v-for": ("Vue.js", "Frontend Framework"),
    "data-reactroot": ("React", "Frontend Framework"),
    "data-server-rendered": ("Vue.js (SSR)", "Frontend Framework"),
    "data-turbo": ("Turbo (Hotwire)", "Frontend Framework"),
    "data-controller": ("Stimulus (Hotwire)", "Frontend Framework"),
    "astro-island": ("Astro", "Frontend Framework"),
}

EXTRA_FORM_SIGNATURES = {
    "wpcf7-form-tag": ("Contact Form 7 (WordPress)", "Plugin"),
    "gform_submit": ("Gravity Forms (WordPress)", "Plugin"),
    "nf-field": ("Ninja Forms (WordPress)", "Plugin"),
    "wc-order-fields": ("WooCommerce", "Plugin"),
}

EXTRA_URL_SIGNATURES = {
    "sentry.io": ("Sentry", "Error Tracking"),
    "newrelic.com": ("New Relic", "Observability"),
    "segment.com": ("Segment", "Analytics"),
    "hubspot.com": ("HubSpot", "Marketing"),
    "intercom.io": ("Intercom", "Customer Support"),
    "zendesk.com": ("Zendesk", "Customer Support"),
    "contentful.com": ("Contentful", "Headless CMS"),
    "sanity.io": ("Sanity", "Headless CMS"),
    "cloudinary.com": ("Cloudinary", "Media/CDN"),
    "algolia.net": ("Algolia Search", "Search"),
    "algolianet.com": ("Algolia Search", "Search"),
}

# ---------- More version-capture patterns for script/link based techs ----------
EXTRA_TECH_VERSION_PATTERNS = {
    "React":
    [r"react[@/-]([\d.]+)", r"react\.production\.min\.js\?v=([\d.]+)"],
    "Vue.js": [r"vue[@/-]([\d.]+)", r"vue\.global\.js\?v=([\d.]+)"],
    "Angular": [r"angular[@/-]([\d.]+)"],
    "Lodash": [r"lodash[@/.-]([\d.]+)"],
    "Moment.js": [r"moment[@/.-]([\d.]+)"],
    "Axios": [r"axios[@/.-]([\d.]+)"],
    "D3.js": [r"d3[@/.v-]([\d.]+)"],
    "Chart.js": [r"chart(?:\.js)?[@/.-]([\d.]+)"],
    "Three.js": [r"three[@/.-]([\d.]+)"],
    "GSAP": [r"gsap[@/.-]([\d.]+)"],
    "Alpine.js": [r"alpinejs?[@/.-]([\d.]+)"],
    "Tailwind CSS": [r"tailwindcss[@/.-]([\d.]+)"],
    "Materialize CSS": [r"materialize[@/.-]([\d.]+)"],
    "Modernizr": [r"modernizr[@/.-]([\d.]+)"],
    "Underscore.js": [r"underscore[@/.-]([\d.]+)"],
    "Popper.js": [r"popper[@/.-]([\d.]+)"],
    "Knockout.js": [r"knockout[@/.-]([\d.]+)"],
    "Backbone.js": [r"backbone[@/.-]([\d.]+)"],
    "Ember.js": [r"ember[@/.-]([\d.]+)"],
    "Preact": [r"preact[@/.-]([\d.]+)"],
    "htmx": [r"htmx\.org@([\d.]+)", r"htmx[@/.-]([\d.]+)"],
    "jQuery UI": [r"jquery-ui[@/.-]([\d.]+)"],
    "Swiper.js":
    [r"swiper[@/.-]([\d.]+)", r"swiper-bundle\.min\.js\?v=([\d.]+)"],
}

TECH_VERSION_PATTERNS.update(EXTRA_TECH_VERSION_PATTERNS)

HEADER_SIGNATURES["Server"].update(EXTRA_HEADER_SIGNATURES["Server"])
HEADER_SIGNATURES["X-Powered-By"].update(
    EXTRA_HEADER_SIGNATURES["X-Powered-By"])

PRESENCE_HEADER_SIGNATURES.update(EXTRA_PRESENCE_HEADER_SIGNATURES)

REVERSE_PROXY_SIGNATURES["Server"].update(
    EXTRA_REVERSE_PROXY_SIGNATURES["Server"])

CDN_SIGNATURES["Server"].update(EXTRA_CDN_SIGNATURES["Server"])
CDN_SIGNATURES["X-Edge-Location"] = EXTRA_CDN_SIGNATURES["X-Edge-Location"]

WAF_SIGNATURES["Server"].update(EXTRA_WAF_SIGNATURES["Server"])

CMS_SIGNATURES["Meta Generator"].update(EXTRA_CMS_META_GENERATOR)

HTML_SIGNATURES.update(EXTRA_HTML_SIGNATURES)
SCRIPT_SIGNATURES.update(EXTRA_SCRIPT_SIGNATURES)
LINK_SIGNATURES.update(EXTRA_LINK_SIGNATURES)
COOKIE_SIGNATURES.update(EXTRA_COOKIE_SIGNATURES)
COOKIE_PREFIX_SIGNATURES.extend(EXTRA_COOKIE_PREFIX_SIGNATURES)
INLINE_JS_SIGNATURES.update(EXTRA_INLINE_JS_SIGNATURES)
DOM_ATTRIBUTE_SIGNATURES.update(EXTRA_DOM_ATTRIBUTE_SIGNATURES)
FORM_SIGNATURES.update(EXTRA_FORM_SIGNATURES)
URL_SIGNATURES.update(EXTRA_URL_SIGNATURES)

# ==========================================================
# REGEX PRECOMPILATION
# All the *_SIGNATURES dicts above store "pattern" as a raw
# string, which every detect_*() call was re-compiling on
# every re.search(). On a large scan this adds up fast. This
# pass walks each dict once at import time and replaces the
# string pattern with a compiled regex object (IGNORECASE
# baked in), so detect_*() just calls pattern.search(value).
# ==========================================================


def _compile_header_style_signatures(signature_dict):
    """
    For dicts shaped like {header: {tech_name: {"pattern": str, ...}}}
    — HEADER_SIGNATURES, REVERSE_PROXY_SIGNATURES, CDN_SIGNATURES,
    WAF_SIGNATURES.
    """
    for _header, technologies in signature_dict.items():
        for _name, info in technologies.items():
            pattern = info.get("pattern")
            if isinstance(pattern, str):
                info["pattern"] = re.compile(pattern, re.I)


def _compile_cms_signatures(cms_dict):
    """
    CMS_SIGNATURES has an extra nesting level (category -> tech -> info)
    but every leaf still carries a "pattern" string, so the same
    replace-in-place approach applies.
    """
    for _category, technologies in cms_dict.items():
        for _name, info in technologies.items():
            pattern = info.get("pattern")
            if isinstance(pattern, str):
                info["pattern"] = re.compile(pattern, re.I)


def _compile_pattern_list_dict(pattern_list_dict):
    """
    For dicts shaped like {tech_name: [pattern_str, ...]} —
    TECH_VERSION_PATTERNS.
    """
    for name, patterns in pattern_list_dict.items():
        pattern_list_dict[name] = [
            re.compile(p, re.I) if isinstance(p, str) else p for p in patterns
        ]


def _compile_flat_pattern_dict(flat_dict):
    """
    For dicts shaped like {tech_name: [pattern_str, ...]} used for
    plain error-message matching — DB_ERROR_PATTERNS.
    """
    for name, patterns in flat_dict.items():
        flat_dict[name] = [
            re.compile(p, re.I) if isinstance(p, str) else p for p in patterns
        ]


_compile_header_style_signatures(HEADER_SIGNATURES)
_compile_header_style_signatures(REVERSE_PROXY_SIGNATURES)
_compile_header_style_signatures(CDN_SIGNATURES)
_compile_header_style_signatures(WAF_SIGNATURES)
_compile_cms_signatures(CMS_SIGNATURES)
_compile_pattern_list_dict(TECH_VERSION_PATTERNS)

# ==========================================================
# ACTIVE-RECON SIGNATURES
# Database fingerprinting, EOL/outdated version rules,
# sensitive-path / admin-panel / API / sourcemap exposure
# checks, and favicon hashing. Purely additive
# ==========================================================

# ---------- Database error-message fingerprints ----------
DB_ERROR_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"mysql_fetch_array\(\)",
        r"mysqli_",
        r"warning:\s*mysql",
        r"supplied argument is not a valid mysql",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"postgresql.*error",
        r"unterminated quoted string at or near",
        r"invalid input syntax for",
    ],
    "Microsoft SQL Server": [
        r"microsoft sql server",
        r"unclosed quotation mark after the character string",
        r"odbc sql server driver",
        r"sqlserverexception",
    ],
    "Oracle": [
        r"ora-\d{5}",
        r"oracle error",
        r"oracle.*driver",
    ],
    "SQLite": [
        r"sqlite3?::",
        r"sqlite_error",
        r"unable to open database file",
        r"sqlite\.oledb",
    ],
    "MongoDB": [
        r"mongoerror",
        r"mongodb\\.driver",
        r"e11000 duplicate key error",
    ],
}

# ---------- Backend/driver hints inside X-Powered-By or similar ----------
DB_HEADER_HINTS = {
    "mysqlnd": "MySQL",
    "pdo_mysql": "MySQL",
    "mysqli": "MySQL",
    "pdo_pgsql": "PostgreSQL",
    "pgsql": "PostgreSQL",
    "sqlsrv": "Microsoft SQL Server",
    "oci8": "Oracle",
}

# ---------- Admin panels (CMS + DB admin tools) ----------
ADMIN_PANEL_PATHS = {
    "/phpmyadmin/": ("phpMyAdmin", "Database Admin Panel"),
    "/pma/": ("phpMyAdmin", "Database Admin Panel"),
    "/phpMyAdmin/": ("phpMyAdmin", "Database Admin Panel"),
    "/adminer.php": ("Adminer", "Database Admin Panel"),
    "/adminer/": ("Adminer", "Database Admin Panel"),
    "/pgadmin4/": ("pgAdmin", "Database Admin Panel"),
    "/wp-admin/": ("WordPress Admin", "CMS Admin Panel"),
    "/wp-login.php": ("WordPress Login", "CMS Admin Panel"),
    "/administrator/": ("Joomla Admin", "CMS Admin Panel"),
    "/user/login": ("Drupal Login", "CMS Admin Panel"),
    "/admin/": ("Generic Admin Panel", "Admin Panel"),
}

# ---------- Sensitive / commonly-forgotten exposed files ----------
SENSITIVE_PATHS = {
    "/.git/config": "Git repository exposure",
    "/.git/HEAD": "Git repository exposure",
    "/.env": "Environment file exposure",
    "/.htaccess": "Apache config exposure",
    "/composer.json": "Composer manifest exposure",
    "/package.json": "NPM manifest exposure",
    "/.DS_Store": "macOS metadata exposure",
    "/web.config": "IIS config exposure",
    "/wp-config.php.bak": "WordPress config backup exposure",
    "/config.php.bak": "Config backup exposure",
    "/.svn/entries": "SVN repository exposure",
    "/backup.zip": "Backup archive exposure",
    "/database.sql": "SQL dump exposure",
    "/dump.sql": "SQL dump exposure",
    "/.aws/credentials": "AWS credentials exposure",
    "/docker-compose.yml": "Docker Compose config exposure",
    "/id_rsa": "SSH private key exposure",
}

# ---------- API / schema discovery paths ----------
API_ENDPOINT_PATHS = {
    "/graphql": "GraphQL API",
    "/api/graphql": "GraphQL API",
    "/swagger.json": "Swagger/OpenAPI spec",
    "/swagger-ui.html": "Swagger UI",
    "/openapi.json": "OpenAPI spec",
    "/api/swagger.json": "Swagger/OpenAPI spec",
    "/.well-known/openid-configuration": "OpenID Connect discovery",
    "/api/v1/": "REST API root",
}

# ---------- Known EOL / vulnerable minimum-safe versions ----------
# value = (minimum_safe_version_tuple, human note)
EOL_VERSION_RULES = {
    "jQuery":
    ((3, 0, 0), "jQuery < 3.0 has known XSS issues (CVE-2020-11022/11023)."),
    "WordPress":
    ((5, 8, 0), "Older WordPress core releases have multiple known CVEs."),
    "PHP":
    ((7, 4, 0), "PHP versions below 7.4 are end-of-life and unsupported."),
    "Bootstrap": ((4, 0, 0),
                  "Bootstrap 3.x has known XSS issues in tooltip/popover."),
    "Drupal":
    ((9, 0, 0),
     "Older Drupal versions have multiple known CVEs (Drupalgeddon family)."),
    "Joomla": ((4, 0, 0), "Older Joomla releases have multiple known CVEs."),
}

# ---------- Favicon hashes (mmh3, Wappalyzer-style) ----------
# Best-effort starter set — extend as you verify real hashes for
# your targets; mechanism works even with an empty dict.
FAVICON_HASHES = {
    # -305179312: ("Jenkins", "CI/CD"),
}

# DB_ERROR_PATTERNS is defined above with raw regex strings; compile them
# once here too, same reasoning as the precompilation pass earlier.
_compile_flat_pattern_dict(DB_ERROR_PATTERNS)


class TechnologyScanner(BaseModule):

    name = "Technology"

    category = "Core"

    description = ("Detect technologies, CMS, frameworks and servers.")

    MAX_CONFIDENCE = 100
    MAX_EVIDENCE_PER_TECH = 5

    def __init__(self):

        super().__init__()

        self.tech = {}

        self.headers = {}

        self.cookies = {}

        self.html = ""

        self.soup = None

        self.server = ""

        self.powered = ""

        self.is_html = True

        self.findings = {
            "database": [],
            "sensitive_files": [],
            "admin_panels": [],
            "api_endpoints": [],
            "sourcemaps": [],
            "outdated": [],
        }

        self.soft_404_status = None
        self.soft_404_length = None

    def prepare(self, scanner):

        self.tech.clear()

        for key in self.findings:
            self.findings[key] = []

        raw_headers = scanner.response.headers

        # Preserve repeated headers (e.g. multiple Set-Cookie) where the
        # underlying headers object supports it, instead of silently
        # collapsing to the last occurrence via dict(...).
        self.headers = {}
        for key in raw_headers.keys():
            if hasattr(raw_headers, "get_list"):
                values = raw_headers.get_list(key)
                self.headers[key] = ", ".join(values) if values else ""
            else:
                self.headers[key] = raw_headers.get(key, "")

        self.cookies = dict(scanner.response.cookies)

        content_type = self.headers.get("Content-Type", "")
        # Treat unknown/empty content-type as HTML-ish rather than skipping
        # detection outright; only explicitly non-text types are excluded.
        self.is_html = ("html" in content_type.lower() or content_type == ""
                        or "text" in content_type.lower())

        self.html = scanner.response.text if self.is_html else ""

        self.soup = BeautifulSoup(
            self.html, "html.parser") if self.html else BeautifulSoup(
                "", "html.parser")

        self.server = self.headers.get("Server", "")

        self.powered = self.headers.get("X-Powered-By", "")

    def add_detection(
        self,
        name,
        category,
        evidence,
        confidence=25,
        version="-",
    ):

        key = name.strip()

        if key not in self.tech:

            self.tech[key] = Technology(
                name=key,
                category=category,
                version=version,
                confidence=min(confidence, self.MAX_CONFIDENCE),
                evidence=[evidence],
            )

            return

        tech = self.tech[key]

        if evidence not in tech.evidence and len(
                tech.evidence) < self.MAX_EVIDENCE_PER_TECH:

            tech.evidence.append(evidence)

        # ---- Confidence: combine like independent probability signals ----
        # A flat sum would let three weak 25%-confidence hits stack to 75%
        # even if none of them individually meant much. Combining them as
        # independent signals (1 - product of "not this tech" probabilities)
        # gives diminishing returns for repeated weak evidence while still
        # letting a couple of strong, independent signals push confidence
        # up quickly — e.g. two 90% hits combine to 99%, not a flat 100%.
        existing_p = tech.confidence / 100
        incoming_p = min(confidence, self.MAX_CONFIDENCE) / 100
        combined_p = 1 - (1 - existing_p) * (1 - incoming_p)

        tech.confidence = round(min(combined_p * 100, self.MAX_CONFIDENCE))

        # reports a genuinely newer version. ----
        new_parsed = self._parse_version(version)
        current_parsed = self._parse_version(tech.version)

        if new_parsed is not None:
            if current_parsed is None or new_parsed > current_parsed:
                tech.version = version

        # ---- Category: only backfill if we somehow recorded an empty
        # one — first non-empty category wins, keeps output stable. ----
        if category and not tech.category:
            tech.category = category

    @staticmethod
    def extract_version(pattern, text):

        match = re.search(
            pattern,
            text,
            re.I,
        )

        if not match:

            return "-"

        if match.groups():

            return match.group(1)

        return "-"

    @staticmethod
    def _parse_version(value: str):
        """
        Best-effort parse of a version string into a comparable tuple
        of ints, e.g. "5.8.1" -> (5, 8, 1). Returns None if nothing
        numeric could be extracted.
        """
        if not value or value == "-":
            return None

        numbers = re.findall(r"\d+", value)

        if not numbers:
            return None

        parts = [int(n) for n in numbers[:3]]

        # Pad to a fixed length so "5.8" and "5.8.0" compare as equal
        # instead of the shorter tuple looking "smaller" by mistake.
        while len(parts) < 3:
            parts.append(0)

        return tuple(parts)

    def html_contains(
        self,
        value,
    ):

        return value.lower() in self.html.lower()

    def header_contains(
        self,
        header,
        value,
    ):

        current = self.headers.get(
            header,
            "",
        )

        return value.lower() in current.lower()

    def cookie_exists(
        self,
        cookie,
    ):

        return cookie in self.cookies

    def meta_generator(self):

        tag = self.soup.find(
            "meta",
            attrs={"name": re.compile(
                "generator",
                re.I,
            )},
        )

        if not tag:

            return ""

        return tag.get(
            "content",
            "",
        )

    # ==========================================================
    # Extract Version From URL
    # ==========================================================

    @staticmethod
    def extract_version_from_url(url: str, technology: str):
        if technology in TECH_VERSION_PATTERNS:
            for pattern in TECH_VERSION_PATTERNS[technology]:
                match = pattern.search(url)
                if match:
                    return match.group(1).strip(".")

        patterns = [
            r'[-@]v?(\d+\.\d+(?:\.\d+)*)',
            r'[?&]v=(\d+\.\d+(?:\.\d+)*)',
            r'/(\d+\.\d+(?:\.\d+)?)/',
        ]

        for pattern in patterns:

            match = re.search(pattern, url, re.I)

            if match:
                return match.group(1).strip(".")

        return "-"

    # ==========================================================
    # Header Detection (regex, per specific header)
    # ==========================================================

    def detect_headers(self):

        for header, technologies in HEADER_SIGNATURES.items():

            value = self.headers.get(header, "")

            if not value:
                continue

            for name, info in technologies.items():

                match = info["pattern"].search(value)

                if not match:
                    continue

                version = "-"

                if match.groups():
                    version = match.group(1) or "-"

                self.add_detection(
                    name=name,
                    category=info["category"],
                    version=version,
                    confidence=100,
                    evidence=f"{header}: {value}",
                )

    # ==========================================================
    # Presence Header Detection (header just needs to exist)
    # ==========================================================

    def detect_presence_headers(self):

        for header, (name, category) in PRESENCE_HEADER_SIGNATURES.items():

            if header in self.headers:

                self.add_detection(
                    name=name,
                    category=category,
                    confidence=80,
                    evidence=f"Header present: {header}",
                )

    # ==========================================================
    # Meta Generator Detection
    # ==========================================================

    def detect_generator(self):

        generator = self.meta_generator()

        if not generator:

            return

        version = self.extract_version(
            r"([\d\.]+)",
            generator,
        )

        self.add_detection(
            name=generator.split()[0],
            category="CMS",
            version=version,
            confidence=90,
            evidence=f"Meta Generator: {generator}",
        )

    # ==========================================================
    # HTML Detection
    # ==========================================================

    def detect_html(self):

        html = self.html.lower()

        for name, info in HTML_SIGNATURES.items():

            for pattern in info["patterns"]:

                if pattern.lower() in html:

                    self.add_detection(
                        name=name,
                        category=info["category"],
                        confidence=60,
                        evidence=f"HTML Pattern: {pattern}",
                    )

    # ==========================================================
    # Cookie Detection (exact name match)
    # ==========================================================

    def detect_cookies(self):

        for cookie, tech in COOKIE_SIGNATURES.items():

            if cookie in self.cookies:

                self.add_detection(
                    name=tech[0],
                    category=tech[1],
                    confidence=90,
                    evidence=f"Cookie: {cookie}",
                )

    # ==========================================================
    # Cookie Prefix Detection (dynamic cookie name suffixes)
    # ==========================================================

    def detect_cookie_prefixes(self):

        for cookie_name in self.cookies:

            for prefix, name, category in COOKIE_PREFIX_SIGNATURES:

                if cookie_name.startswith(prefix):

                    self.add_detection(
                        name=name,
                        category=category,
                        confidence=80,
                        evidence=f"Cookie: {cookie_name}",
                    )

    # ==========================================================
    # Script Detection
    # ==========================================================

    def detect_scripts(self):

        for script in self.soup.find_all("script", src=True):

            src = script.get("src", "").lower()

            for signature, tech in SCRIPT_SIGNATURES.items():

                if signature not in src:
                    continue

                version = self.extract_version_from_url(src, tech[0])

                self.add_detection(
                    name=tech[0],
                    category=tech[1],
                    version=version,
                    confidence=70,
                    evidence=f"Script: {src}",
                )

    # ==========================================================
    # Link Detection (stylesheets, fonts, CDN-hosted assets)
    # ==========================================================

    def detect_links(self):

        for link in self.soup.find_all("link", href=True):

            href = link.get("href", "").lower()

            for signature, tech in LINK_SIGNATURES.items():

                if signature not in href:
                    continue
                version = self.extract_version_from_url(href, tech[0])

                self.add_detection(
                    name=tech[0],
                    category=tech[1],
                    version=version,
                    confidence=70,
                    evidence=f"Link: {href}",
                )

    # ==========================================================
    # Inline JavaScript Detection
    # ==========================================================

    def detect_inline_scripts(self):

        for script in self.soup.find_all("script"):

            if script.get("src"):
                continue

            code = script.get_text(" ", strip=True)

            if not code:
                continue

            lower = code.lower()

            for pattern, tech in INLINE_JS_SIGNATURES.items():

                if pattern.lower() in lower:

                    self.add_detection(name=tech[0],
                                       category=tech[1],
                                       confidence=75,
                                       evidence=f"Inline JS: {pattern}")

    # ==========================================================
    # DOM Attribute Detection
    # ==========================================================

    def detect_dom_attributes(self):

        for tag in self.soup.find_all(True):

            for attr in tag.attrs:

                attr = attr.lower()

                if attr in DOM_ATTRIBUTE_SIGNATURES:

                    tech = DOM_ATTRIBUTE_SIGNATURES[attr]

                    self.add_detection(name=tech[0],
                                       category=tech[1],
                                       confidence=70,
                                       evidence=f"DOM Attribute: {attr}")

    # ==========================================================
    # URL Detection
    # ==========================================================

    def detect_urls(self):

        html = self.html.lower()

        for signature, tech in URL_SIGNATURES.items():

            if signature.lower() in html:

                self.add_detection(name=tech[0],
                                   category=tech[1],
                                   confidence=70,
                                   evidence=f"URL: {signature}")

    # ==========================================================
    # Form Detection
    # ==========================================================

    def detect_forms(self):

        for form in self.soup.find_all("form"):

            for element in form.find_all(["input", "textarea", "select"]):

                name = (element.get("name") or "").strip()
                element_id = (element.get("id") or "").strip()

                for field in (name, element_id):

                    if not field:
                        continue

                    if field in FORM_SIGNATURES:

                        tech = FORM_SIGNATURES[field]

                        self.add_detection(name=tech[0],
                                           category=tech[1],
                                           confidence=80,
                                           evidence=f"Form Field: {field}")

    # ==========================================================
    # Operating System Detection
    # ==========================================================

    def detect_operating_system(self):

        headers = "\n".join(f"{k}: {v}"
                            for k, v in self.headers.items()).lower()

        html = self.html.lower()

        for os_name, info in OS_SIGNATURES.items():

            # ---------- Header Detection ----------
            for pattern in info["headers"]:

                if pattern.lower() in headers:

                    self.add_detection(
                        name=os_name,
                        category=info["category"],
                        confidence=100,
                        evidence=f"Header: {pattern}",
                    )

                    break

            # ---------- HTML Detection ----------
            for pattern in info["html"]:

                if pattern.lower() in html:

                    self.add_detection(
                        name=os_name,
                        category=info["category"],
                        confidence=80,
                        evidence=f"HTML: {pattern}",
                    )

                    break

    # ==========================================================
    # Reverse Proxy Detection
    # ==========================================================

    def detect_reverse_proxy(self):

        for header, technologies in REVERSE_PROXY_SIGNATURES.items():

            value = self.headers.get(header, "")

            if not value:
                continue

            for name, info in technologies.items():

                match = info["pattern"].search(value)

                if not match:
                    continue

                version = "-"

                if match.groups():
                    version = match.group(1) or "-"

                self.add_detection(
                    name=name,
                    category=info["category"],
                    version=version,
                    confidence=100,
                    evidence=f"{header}: {value}",
                )

    # ==========================================================
    # CDN Detection
    # ==========================================================

    def detect_cdn(self):

        for header, technologies in CDN_SIGNATURES.items():

            value = self.headers.get(header, "")

            if not value:
                continue

            for name, info in technologies.items():

                match = info["pattern"].search(value)

                if not match:
                    continue

                version = "-"

                if match.groups():
                    version = match.group(1) or "-"

                self.add_detection(
                    name=name,
                    category=info["category"],
                    version=version,
                    confidence=100,
                    evidence=f"{header}: {value}",
                )

    # ==========================================================
    # WAF Detection
    # ==========================================================

    def detect_waf(self):

        for header, technologies in WAF_SIGNATURES.items():

            value = self.headers.get(header, "")

            if not value:
                continue

            for name, info in technologies.items():

                match = info["pattern"].search(value)

                if not match:
                    continue

                self.add_detection(
                    name=name,
                    category=info["category"],
                    version="-",
                    confidence=100,
                    evidence=f"{header}: {value}",
                )

    # ==========================================================
    # CMS Detection
    # ==========================================================

    def detect_cms(self):

        headers = self.headers
        html = self.html or ""

        # ----------------------------------------
        # Meta Generator
        # ----------------------------------------

        generator = self.soup.find(
            "meta", attrs={"name": re.compile(r"generator", re.I)})

        if generator and generator.get("content"):

            content = generator["content"]

            for tech, data in CMS_SIGNATURES.get("Meta Generator", {}).items():

                match = data["pattern"].search(content)

                if not match:
                    continue

                version = "-"

                if match.groups():
                    version = match.group(1) or "-"

                self.add_detection(
                    name=tech,
                    category=data["category"],
                    version=version,
                    confidence=70,
                    evidence=f"Meta Generator: {content}",
                )

        # ----------------------------------------
        # Header Detection
        # ----------------------------------------

        for tech, data in CMS_SIGNATURES.get("Header", {}).items():

            header_name = data["header"]

            if header_name not in headers:
                continue

            value = headers.get(header_name, "")

            if data["pattern"].search(value):

                self.add_detection(
                    name=tech,
                    category=data["category"],
                    confidence=70,
                    evidence=f"{header_name}: {value}",
                )

        # ----------------------------------------
        # X-Powered-By
        # ----------------------------------------

        powered = headers.get("X-Powered-By", "")

        for tech, data in CMS_SIGNATURES.get("X-Powered-By", {}).items():

            if data["pattern"].search(powered):

                self.add_detection(
                    name=tech,
                    category=data["category"],
                    confidence=70,
                    evidence=f"X-Powered-By: {powered}",
                )

        # ----------------------------------------
        # HTML Detection
        # ----------------------------------------

        for tech, data in CMS_SIGNATURES.get("HTML", {}).items():

            if data["pattern"].search(html):

                self.add_detection(
                    name=tech,
                    category=data["category"],
                    confidence=70,
                    evidence=f"HTML Pattern: {data['pattern'].pattern}",
                )

        # ----------------------------------------
        # Script Detection
        # ----------------------------------------

        for script in self.soup.find_all("script", src=True):

            src = script.get("src", "")

            for tech, data in CMS_SIGNATURES.get("Script", {}).items():

                if data["pattern"].search(src):

                    self.add_detection(
                        name=tech,
                        category=data["category"],
                        confidence=70,
                        evidence=f"Script: {src}",
                    )

        # ----------------------------------------
        # Cookie Detection
        # ----------------------------------------

        cookies = "; ".join(self.cookies.keys())

        for tech, data in CMS_SIGNATURES.get("Cookie", {}).items():

            if data["pattern"].search(cookies):

                self.add_detection(
                    name=tech,
                    category=data["category"],
                    confidence=70,
                    evidence=f"Cookies: {cookies}",
                )

    # ==========================================================
    # Database Fingerprinting
    # Error-message pattern match against page body + driver
    # hints inside X-Powered-By / similar headers.
    # ==========================================================

    def detect_database(self):

        haystack = self.html if self.is_html else ""

        for db_name, patterns in DB_ERROR_PATTERNS.items():

            for pattern in patterns:

                if pattern.search(haystack):

                    self.add_detection(
                        name=db_name,
                        category="Database",
                        confidence=85,
                        evidence=f"Error pattern matched: {pattern.pattern}",
                    )

                    self.findings["database"].append(
                        f"{db_name} — error-based fingerprint ({pattern.pattern})"
                    )

                    break  # one hit per DB is enough evidence

        powered_lower = self.powered.lower()

        for hint, db_name in DB_HEADER_HINTS.items():

            if hint in powered_lower:

                self.add_detection(
                    name=db_name,
                    category="Database",
                    confidence=70,
                    evidence=f"X-Powered-By: {self.powered}",
                )

                self.findings["database"].append(
                    f"{db_name} — driver hint in X-Powered-By ({hint})")

    # ==========================================================
    # Outdated / EOL Version Flagging (added — 0ct0pu3 update)
    # ==========================================================

    def flag_outdated(self):

        for tech in list(self.tech.values()):

            if tech.name not in EOL_VERSION_RULES:
                continue

            min_safe, note = EOL_VERSION_RULES[tech.name]

            current = self._parse_version(tech.version)

            if current is None:
                continue

            if current < min_safe:

                self.findings["outdated"].append(
                    f"{tech.name} {tech.version} — {note}")

                if len(tech.evidence) < self.MAX_EVIDENCE_PER_TECH:
                    tech.evidence.append(f"Outdated: {note}")

    # ==========================================================
    # Active Recon Helpers
    # Network-bound checks: sensitive files, admin panels, API
    # endpoints, exposed source maps, favicon hashing, and
    # robots.txt/sitemap.xml parsing. All best-effort — network
    # errors are swallowed so one failed probe never aborts the
    # whole module.
    # ==========================================================

    @staticmethod
    def _base_url(scanner):
        parsed = urlparse(scanner.target)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _detect_soft_404(self, scanner):
        """
        Probe a random, almost-certainly-nonexistent path once and
        remember its status/length, so later exposure checks can
        tell a real 200 apart from a catch-all "soft 404" page that
        returns 200 for everything.
        """

        base = self._base_url(scanner)
        random_path = f"/__nonexistent_{uuid.uuid4().hex}__"
        url = urljoin(base, random_path)

        try:
            response = await scanner.client.get(url, timeout=8)
        except Exception:
            self.soft_404_status = None
            self.soft_404_length = None
            return

        if response is not None:
            self.soft_404_status = response.status_code
            self.soft_404_length = len(response.content or b"")

    def _is_real_hit(self, response) -> bool:

        if response is None or response.status_code != 200:
            return False

        content_len = len(response.content or b"")

        if content_len == 0:
            return False

        if self.soft_404_status == 200 and self.soft_404_length is not None:
            if abs(content_len - self.soft_404_length) < 50:
                # Looks like the same catch-all page the random path got.
                return False

        return True

    async def detect_sensitive_files(self, scanner):

        base = self._base_url(scanner)

        for path, label in SENSITIVE_PATHS.items():

            url = urljoin(base, path)

            try:
                response = await scanner.client.get(url,
                                                    timeout=8,
                                                    follow_redirects=False)
            except Exception:
                continue

            if not self._is_real_hit(response):
                continue

            self.findings["sensitive_files"].append(f"{path} — {label}")

            self.add_detection(
                name=label,
                category="Exposed File",
                confidence=90,
                evidence=f"HTTP 200: {path}",
            )

    async def detect_admin_panels(self, scanner):

        base = self._base_url(scanner)

        for path, (name, category) in ADMIN_PANEL_PATHS.items():

            url = urljoin(base, path)

            try:
                response = await scanner.client.get(url,
                                                    timeout=8,
                                                    follow_redirects=True)
            except Exception:
                continue

            if not self._is_real_hit(response):
                continue

            self.findings["admin_panels"].append(f"{path} — {name}")

            self.add_detection(
                name=name,
                category=category,
                confidence=75,
                evidence=f"Accessible: {path} (HTTP {response.status_code})",
            )

    async def detect_api_endpoints(self, scanner):

        base = self._base_url(scanner)

        for path, label in API_ENDPOINT_PATHS.items():

            url = urljoin(base, path)

            try:
                response = await scanner.client.get(url,
                                                    timeout=8,
                                                    follow_redirects=True)
            except Exception:
                continue

            if response is None or response.status_code not in (200, 400, 401,
                                                                403):
                continue

            if response.status_code == 200 and not self._is_real_hit(response):
                continue

            self.findings["api_endpoints"].append(
                f"{path} — {label} (HTTP {response.status_code})")

            self.add_detection(
                name=label,
                category="API",
                confidence=60,
                evidence=f"{path} responded HTTP {response.status_code}",
            )

    async def detect_sourcemaps(self, scanner):

        base = self._base_url(scanner)
        checked = set()

        for script in self.soup.find_all("script", src=True):

            src = script.get("src", "")

            if not src.endswith(".js") or src in checked:
                continue

            checked.add(src)

            if len(checked) > 10:
                # Cap how many script sources we probe per run.
                break

            map_url = urljoin(base, src + ".map")

            try:
                response = await scanner.client.get(map_url, timeout=8)
            except Exception:
                continue

            if not self._is_real_hit(response):
                continue

            self.findings["sourcemaps"].append(map_url)

            self.add_detection(
                name="Exposed Source Map",
                category="Information Disclosure",
                confidence=85,
                evidence=f"HTTP 200: {map_url}",
            )

    async def detect_favicon(self, scanner):

        try:
            import mmh3
        except ImportError:
            # Optional dependency not installed — skip this check
            # without failing the module.
            return

        if not FAVICON_HASHES:
            # No reference hashes configured yet, nothing to match against.
            return

        base = self._base_url(scanner)
        url = urljoin(base, "/favicon.ico")

        try:
            response = await scanner.client.get(url, timeout=8)
        except Exception:
            return

        if response is None or response.status_code != 200 or not response.content:
            return

        try:
            encoded = base64.encodebytes(response.content)
            fav_hash = mmh3.hash(encoded)
        except Exception:
            return

        if fav_hash in FAVICON_HASHES:

            name, category = FAVICON_HASHES[fav_hash]

            self.add_detection(
                name=name,
                category=category,
                confidence=95,
                evidence=f"Favicon hash match: {fav_hash}",
            )

    async def detect_robots_sitemap(self, scanner):

        base = self._base_url(scanner)

        for path in ("/robots.txt", "/sitemap.xml"):

            url = urljoin(base, path)

            try:
                response = await scanner.client.get(url, timeout=8)
            except Exception:
                continue

            if response is None or response.status_code != 200:
                continue

            text = response.text if hasattr(response, "text") else ""
            lower = text.lower()

            if "wp-admin" in lower or "wp-includes" in lower:

                self.add_detection(
                    name="WordPress",
                    category="CMS",
                    confidence=40,
                    evidence=f"{path}: WordPress path reference",
                )

            if "/administrator/" in lower:

                self.add_detection(
                    name="Joomla",
                    category="CMS",
                    confidence=30,
                    evidence=f"{path}: Joomla path reference",
                )

            if "/user/" in lower and "drupal" not in lower:

                self.add_detection(
                    name="Drupal",
                    category="CMS",
                    confidence=20,
                    evidence=f"{path}: Drupal-style path reference",
                )

    # ==========================================================
    # Run All (passive) Detectors
    # ==========================================================

    def detect(self):

        self.detect_headers()

        self.detect_presence_headers()

        self.detect_generator()

        self.detect_html()

        self.detect_operating_system()

        self.detect_reverse_proxy()

        self.detect_cdn()

        self.detect_waf()

        self.detect_cms()

        self.detect_scripts()

        self.detect_inline_scripts()

        self.detect_dom_attributes()

        self.detect_links()

        self.detect_urls()

        self.detect_forms()

        self.detect_cookies()

        self.detect_cookie_prefixes()

        self.detect_database()

    # ==========================================================
    # Scoring
    # Not a "how many techs did we find" score — a security
    # exposure score based on what active recon turned up.
    # ==========================================================

    def compute_score(self):

        max_score = 30
        score = max_score

        score -= len(self.findings["sensitive_files"]) * 5
        score -= len(self.findings["admin_panels"]) * 3
        score -= len(self.findings["sourcemaps"]) * 3
        score -= len(self.findings["outdated"]) * 4

        score = max(min(score, max_score), 0)

        return score, max_score

    # ==========================================================
    # JSON Export
    # Structured output other modules (e.g. a future CVE
    # correlation module) can consume directly.
    # ==========================================================

    def to_json(self):

        return {
            "technologies": [{
                "name": t.name,
                "category": t.category,
                "version": t.version,
                "confidence": t.confidence,
                "evidence": t.evidence,
            } for t in sorted(
                self.tech.values(),
                key=lambda x: (-x.confidence, x.category, x.name),
            )],
            "findings":
            self.findings,
        }

    # ==========================================================
    # Console Output
    # ==========================================================

    def build_console(self):

        table = Table(title="Technology Detection")

        table.add_column("Category", style="cyan")
        table.add_column("Technology", style="green")
        table.add_column("Version", style="yellow")
        table.add_column("Confidence", justify="right")

        for tech in sorted(
                self.tech.values(),
                key=lambda x: (-x.confidence, x.category, x.name),
        ):
            table.add_row(
                tech.category,
                tech.name,
                tech.version,
                f"{tech.confidence}%",
            )

        return table

    def _build_description(self):

        return (
            f"{len(self.tech)} technolog(y/ies) detected, "
            f"{len(self.findings['database'])} database hint(s), "
            f"{len(self.findings['sensitive_files'])} exposed file(s), "
            f"{len(self.findings['admin_panels'])} accessible admin panel(s), "
            f"{len(self.findings['sourcemaps'])} exposed source map(s), "
            f"{len(self.findings['outdated'])} outdated technolog(y/ies).")

    # ==========================================================
    # Run
    # ==========================================================

    async def run(self, scanner):

        self.prepare(scanner)

        # ---- Passive detection (no extra network calls) ----
        self.detect()

        # ---- Active recon (extra network calls) ----
        client = getattr(scanner, "client", None)

        if client is not None:

            try:
                await self._detect_soft_404(scanner)
                await self.detect_sensitive_files(scanner)
                await self.detect_admin_panels(scanner)
                await self.detect_api_endpoints(scanner)
                await self.detect_sourcemaps(scanner)
                await self.detect_favicon(scanner)
                await self.detect_robots_sitemap(scanner)
            except Exception as e:
                scanner.console.print(
                    f"[yellow]Technology module: active recon partially failed ({e}).[/yellow]"
                )
        else:
            scanner.console.print(
                "[yellow]Technology module: no HTTP client available, "
                "skipping active recon (sensitive files, admin panels, etc).[/yellow]"
            )

        self.flag_outdated()

        score, max_score = self.compute_score()

        scanner.console.print(self.build_console())

        rows = []

        for tech in sorted(
                self.tech.values(),
                key=lambda x: (-x.confidence, x.category, x.name),
        ):
            rows.append([
                tech.category,
                tech.name,
                tech.version,
                f"{tech.confidence}%",
                "\n".join(tech.evidence),
            ])

        scanner.report.add_module(
            self.name,
            Report.table(
                title="Technology Detection",
                columns=[
                    "Category",
                    "Technology",
                    "Version",
                    "Confidence",
                    "Evidence",
                ],
                rows=rows,
                score=score,
                max_score=max_score,
                description=self._build_description(),
            ),
        )

        if self.findings["database"]:
            scanner.report.add_module(
                "tech_database",
                Report.list(
                    title="Database Fingerprint Hints",
                    items=self.findings["database"],
                    score=0,
                    max_score=0,
                    description=
                    "Indirect signals about the backing database engine.",
                ),
            )

        if self.findings["sensitive_files"]:
            scanner.report.add_module(
                "tech_sensitive_files",
                Report.list(
                    title="Exposed Sensitive Files",
                    items=self.findings["sensitive_files"],
                    score=0,
                    max_score=0,
                    description=
                    "Potentially sensitive files/paths accessible on the target.",
                ),
            )

        if self.findings["admin_panels"]:
            scanner.report.add_module(
                "tech_admin_panels",
                Report.list(
                    title="Accessible Admin Panels",
                    items=self.findings["admin_panels"],
                    score=0,
                    max_score=0,
                    description=
                    "Admin/DB-admin panels reachable without authentication checks.",
                ),
            )

        if self.findings["api_endpoints"]:
            scanner.report.add_module(
                "tech_api_endpoints",
                Report.list(
                    title="Discovered API Endpoints",
                    items=self.findings["api_endpoints"],
                    score=0,
                    max_score=0,
                    description=
                    "API/schema-discovery paths that responded on the target.",
                ),
            )

        if self.findings["sourcemaps"]:
            scanner.report.add_module(
                "tech_sourcemaps",
                Report.list(
                    title="Exposed Source Maps",
                    items=self.findings["sourcemaps"],
                    score=0,
                    max_score=0,
                    description="JavaScript source maps exposed in production, "
                    "which can leak original source code.",
                ),
            )

        if self.findings["outdated"]:
            scanner.report.add_module(
                "tech_outdated",
                Report.list(
                    title="Outdated / EOL Technologies",
                    items=self.findings["outdated"],
                    score=0,
                    max_score=0,
                    description=
                    "Detected technologies below their known-safe minimum version.",
                ),
            )
