from flask import Flask, render_template, request, jsonify
from features.url_analyzer import analyze_url
from features.content_analyzer import analyze_content
from features.email_analyzer import analyze_email
from models.classifier import WebsiteClassifier
import requests
from urllib.parse import urlparse

app = Flask(__name__)
classifier = WebsiteClassifier()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/cyber-stats')
def cyber_stats():
    return render_template('cyber_stats.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Basic URL validation
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Analyze URL features
        url_features = analyze_url(url)
        
        # Analyze content features
        content_features = analyze_content(url)
        
        # Combine features
        features = {**url_features, **content_features}
        
        # Make prediction
        prediction = classifier.predict(features)
        
        return jsonify({
            'url': url,
            'prediction': prediction,
            'features': features
        })
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Error accessing URL: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/check-email', methods=['POST'])
def check_email():
    try:
        email = request.form.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400

        features = analyze_email(email)
        risk_score = sum(1 for value in features.values() if value is True)
        risk_level = 'High' if risk_score >= 3 else 'Medium' if risk_score >= 1 else 'Low'

        return jsonify({
            'risk_level': risk_level,
            'risk_score': risk_score,
            'features': features
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cyber-world')
def cyber_world():
    return render_template('cyber_world.html')

@app.route('/cyber-attack-animation')
def cyber_attack_animation():
    return render_template('cyber_attack_animation.html')

if __name__ == '__main__':
    app.run(debug=True) 