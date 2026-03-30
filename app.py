"""
PhishIris - Main Flask Application
Advanced Phishing Detection & SOC Dashboard
"""

import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from datetime import datetime
import logging

# Import local modules
from parser import EmailParser
from ioc_extractor import IOCExtractor
from detector import PhishingDetector
from vt_lookup import VirusTotalLookup

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'eml', 'msg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize modules
email_parser = EmailParser()
ioc_extractor = IOCExtractor()
phishing_detector = PhishingDetector()
vt_lookup = VirusTotalLookup(api_key=os.environ.get('VT_API_KEY'))


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def format_timestamp():
    """Get formatted timestamp"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')


@app.route('/')
def index():
    """Render main input page"""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze email content"""
    try:
        email_content = None
        filename = None
        
        # Check for file upload
        if 'email_file' in request.files:
            file = request.files['email_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                with open(filepath, 'rb') as f:
                    email_content = f.read()
                
                # Clean up
                try:
                    os.remove(filepath)
                except:
                    pass
        
        # Check for text input
        if not email_content and request.form.get('email_text'):
            email_content = request.form.get('email_text').encode('utf-8')
            filename = 'pasted_email.txt'
        
        if not email_content:
            flash('Please provide email content or upload a file.', 'error')
            return redirect(url_for('index'))
        
        # Parse email
        logger.info("Parsing email content...")
        parsed_email = email_parser.parse_raw_email(email_content)
        
        # Extract IOCs
        logger.info("Extracting IOCs...")
        iocs = ioc_extractor.extract_all(
            parsed_email.get('body', '') + ' ' + parsed_email.get('html_body', ''),
            parsed_email.get('urls', [])
        )
        
        # Enrich with threat intelligence
        logger.info("Enriching with threat intelligence...")
        enriched_iocs = vt_lookup.enrich_iocs(iocs)
        
        # Detect phishing
        logger.info("Running phishing detection...")
        analysis_result = phishing_detector.analyze(parsed_email, enriched_iocs)
        
        # Prepare dashboard data
        dashboard_data = {
            'timestamp': format_timestamp(),
            'filename': filename,
            'email': parsed_email,
            'iocs': enriched_iocs,
            'analysis': analysis_result,
            'scan_id': secrets.token_hex(8).upper()
        }
        
        logger.info(f"Analysis complete. Risk Level: {analysis_result['risk_level']['level']}")
        
        return render_template('dashboard.html', data=dashboard_data)
    
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        flash(f'Error analyzing email: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for programmatic access"""
    try:
        data = request.get_json()
        if not data or 'email_content' not in data:
            return jsonify({'error': 'No email content provided'}), 400
        
        email_content = data['email_content'].encode('utf-8')
        
        # Parse and analyze
        parsed_email = email_parser.parse_raw_email(email_content)
        iocs = ioc_extractor.extract_all(
            parsed_email.get('body', '') + ' ' + parsed_email.get('html_body', ''),
            parsed_email.get('urls', [])
        )
        enriched_iocs = vt_lookup.enrich_iocs(iocs)
        analysis_result = phishing_detector.analyze(parsed_email, enriched_iocs)
        
        return jsonify({
            'success': True,
            'analysis': analysis_result,
            'iocs': enriched_iocs,
            'email_headers': parsed_email.get('headers', {})
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(url_for('index'))


@app.errorhandler(500)
def server_error(e):
    """Handle server error"""
    flash('Server error occurred. Please try again.', 'error')
    return redirect(url_for('index'))


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                     PhishIris v1.0                        ║
    ║        Advanced Phishing Detection & SOC Dashboard        ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Starting server on http://127.0.0.1:5000                 ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)
