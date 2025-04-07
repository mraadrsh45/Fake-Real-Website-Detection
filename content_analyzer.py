import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

def analyze_content(url):
    features = {}
    
    try:
        # Fetch webpage content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Content features
        features['has_login_form'] = bool(soup.find('form', {'action': re.compile(r'login|signin|sign-in', re.I)}))
        features['has_password_input'] = bool(soup.find('input', {'type': 'password'}))
        
        # Count forms
        forms = soup.find_all('form')
        features['num_forms'] = len(forms)
        
        # Count external links
        external_links = 0
        domain = urlparse(url).netloc
        for link in soup.find_all('a', href=True):
            if domain not in link['href'] and link['href'].startswith(('http://', 'https://')):
                external_links += 1
        features['num_external_links'] = external_links
        
        # Count images
        features['num_images'] = len(soup.find_all('img'))
        
        # Check for common phishing indicators
        features['has_suspicious_keywords'] = bool(re.search(
            r'verify|account|security|login|password|bank|paypal|amazon|ebay|apple|microsoft',
            soup.text.lower()
        ))
        
        # Check for SSL certificate
        features['has_valid_ssl'] = url.startswith('https://')
        
        # Content length
        features['content_length'] = len(soup.text)
        
    except Exception as e:
        # If we can't access the content, set default values
        features.update({
            'has_login_form': False,
            'has_password_input': False,
            'num_forms': 0,
            'num_external_links': 0,
            'num_images': 0,
            'has_suspicious_keywords': False,
            'has_valid_ssl': False,
            'content_length': 0
        })
    
    return features 