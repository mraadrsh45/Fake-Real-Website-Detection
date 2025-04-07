from urllib.parse import urlparse
import re
from tld import get_tld
import whois
from datetime import datetime

def analyze_url(url):
    features = {}
    
    # Parse URL
    parsed = urlparse(url)
    
    # Basic URL features
    features['url_length'] = len(url)
    features['has_https'] = parsed.scheme == 'https'
    features['num_subdomains'] = len(parsed.netloc.split('.')) - 2
    features['has_ip'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc))
    
    # Domain features
    try:
        domain_info = get_tld(url, as_object=True)
        features['domain_length'] = len(domain_info.domain)
        features['tld_length'] = len(domain_info.tld)
    except:
        features['domain_length'] = 0
        features['tld_length'] = 0
    
    # Special characters in URL
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_ampersands'] = url.count('&')
    
    # Domain age
    try:
        domain = whois.whois(parsed.netloc)
        if domain.creation_date:
            if isinstance(domain.creation_date, list):
                creation_date = domain.creation_date[0]
            else:
                creation_date = domain.creation_date
            age = (datetime.now() - creation_date).days
            features['domain_age_days'] = age
        else:
            features['domain_age_days'] = 0
    except:
        features['domain_age_days'] = 0
    
    return features 