import re
import tldextract

def has_ip(url):
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    return bool(re.search(ip_pattern, url))

def get_url_length(url):
    return len(url)

def has_at_symbol(url):
    return "@" in url

def count_dots(url):
    return url.count(".")

def count_slashes(url):
    return url.count("/")

def has_https(url):
    return url.startswith("https")

def get_subdomain_count(url):
    extracted = tldextract.extract(url)
    if extracted.subdomain:
        return extracted.subdomain.count(".") + 1
    return 0

def suspicious_words(url):
    keywords = ["secure", "login", "verify", "update", "bank", "free", "signin", "bonus"]
    return any(word in url.lower() for word in keywords)

def extract_features(url):
    return [
        get_url_length(url),
        int(has_ip(url)),
        int(has_at_symbol(url)),
        count_dots(url),
        count_slashes(url),
        int(has_https(url)),
        get_subdomain_count(url),
        int(suspicious_words(url)),
    ]
