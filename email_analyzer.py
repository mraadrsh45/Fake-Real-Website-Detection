import re
from email_validator import validate_email, EmailNotValidError
import dns.resolver
import socket
import whois
from datetime import datetime

def analyze_email(email):
    features = {}
    
    try:
        # Basic email validation
        valid = validate_email(email)
        features['is_valid_format'] = True
        features['domain'] = valid.domain
        
        # Check for suspicious patterns
        features['has_suspicious_chars'] = bool(re.search(r'[^\w\.@-]', email))
        features['has_multiple_dots'] = bool(re.search(r'\.{2,}', email))
        features['has_uppercase'] = bool(re.search(r'[A-Z]', email))
        features['has_numbers'] = bool(re.search(r'\d', email))
        features['has_special_chars'] = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', email))
        
        # Check domain age
        try:
            domain_info = whois.whois(valid.domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                age = (datetime.now() - creation_date).days
                features['domain_age_days'] = age
            else:
                features['domain_age_days'] = 0
        except:
            features['domain_age_days'] = 0
        
        # Check for disposable email domains
        disposable_domains = [
            'tempmail.com', 'mailinator.com', 'guerrillamail.com',
            'yopmail.com', 'throwawaymail.com', 'temp-mail.org'
        ]
        features['is_disposable'] = valid.domain in disposable_domains
        
        # Check for common phishing patterns
        features['has_common_phishing_words'] = bool(re.search(
            r'secure|verify|account|update|login|password|bank|paypal|amazon|ebay|apple|microsoft',
            email.lower()
        ))
        
        # Check for suspicious domain patterns
        features['has_suspicious_domain'] = bool(re.search(
            r'\.(xyz|top|club|online|site|website|space|tech|store|shop|blog|press|host|webcam|party|gq|cf|ml|tk)$',
            valid.domain
        ))
        
        # Check for domain MX records
        try:
            mx_records = dns.resolver.resolve(valid.domain, 'MX')
            features['has_mx_records'] = len(mx_records) > 0
        except:
            features['has_mx_records'] = False
        
        # Calculate risk score
        risk_score = 0
        if features['has_suspicious_chars']: risk_score += 1
        if features['has_multiple_dots']: risk_score += 1
        if features['is_disposable']: risk_score += 2
        if features['has_common_phishing_words']: risk_score += 1
        if features['has_suspicious_domain']: risk_score += 1
        if not features['has_mx_records']: risk_score += 1
        if features['domain_age_days'] < 30: risk_score += 1
        
        features['risk_score'] = min(risk_score, 5)  # Max risk score of 5
        
    except EmailNotValidError:
        features = {
            'is_valid_format': False,
            'domain': None,
            'has_suspicious_chars': False,
            'has_multiple_dots': False,
            'has_uppercase': False,
            'has_numbers': False,
            'has_special_chars': False,
            'domain_age_days': 0,
            'is_disposable': False,
            'has_common_phishing_words': False,
            'has_suspicious_domain': False,
            'has_mx_records': False,
            'risk_score': 5
        }
    
    return features 