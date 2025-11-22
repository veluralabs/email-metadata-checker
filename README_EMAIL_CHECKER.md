# Email Metadata Security Checker

Comprehensive email security analysis tool with weighted scoring system.

## Features

### Weighted Category Analysis (Total: 100%)

1. **Authentication & Transport (25%)**
   - SPF (Sender Policy Framework)
   - DKIM (DomainKeys Identified Mail)
   - DMARC (Domain-based Message Authentication)
   - ARC (Authenticated Received Chain)
   - TLS/SSL cipher inspection

2. **Sender & Domain Intelligence (20%)**
   - Domain age and registration history
   - WHOIS privacy detection
   - TLD (Top-Level Domain) risk assessment
   - RDAP integration

3. **IP/ASN Reputation (15%)**
   - IP reputation analysis
   - Geolocation and geovelocity
   - ASN (Autonomous System Number) risk scoring
   - VPN/proxy detection

4. **URL Intelligence (20%)**
   - Homograph attack detection (punycode)
   - Typosquatting analysis
   - Redirect chain analysis
   - Suspicious URL patterns

5. **Attachment Metadata (10%)**
   - MIME/extension mismatch detection
   - Macro-enabled file detection
   - File hash computation
   - Magic byte analysis

6. **Behavioral Proxies (10%)**
   - First-time sender detection
   - Time anomaly analysis
   - Reply-To mismatch detection

## Installation

### Option 1: Using the Setup Script (Recommended)

```bash
# 1. Create virtual environment
python3 -m venv venv

# 2. Activate virtual environment
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the checker
python3 email_metadata_checker.py
```

### Option 2: Quick Run Script

```bash
# Use the convenience script
./run_email_checker.sh
```

### Dependencies
- Python 3.7+
- dnspython
- python-whois
- requests

## Usage

### Basic Usage (Domain Only)
```bash
source venv/bin/activate
python3 email_metadata_checker.py
```

Then enter:
- Email: `example@domain.com`
- Sender IP: (press Enter to skip)
- Email body: (press Enter to skip)

### Advanced Usage (Full Analysis)
```bash
source venv/bin/activate
python3 email_metadata_checker.py
```

Then provide:
- Email: `sender@example.com`
- Sender IP: `8.8.8.8`
- Email body: Paste the email content (press Enter twice when done)

### Programmatic Usage
```python
from email_metadata_checker import EmailDomainChecker

# Basic check
checker = EmailDomainChecker("sender@example.com")
checker.analyze()

# Full check with all parameters
checker = EmailDomainChecker(
    email="sender@example.com",
    sender_ip="192.168.1.1",
    email_body="Check out this link: https://example.com",
    attachments=[{
        'filename': 'document.pdf',
        'content': b'%PDF...',
        'mime_type': 'application/pdf'
    }]
)
checker.analyze()
```

## Output

The script provides:
- **Category Scores**: Individual scores for each of the 6 categories
- **Weighted Final Score**: Overall security score (0-100)
- **Risk Level**: From LOW to CRITICAL based on final score
- **Visual Score Bars**: Easy-to-read progress bars (█████░░░░░) for each check
- **Detailed Analysis**: Comprehensive information for every check
- **Category Contribution**: Breakdown showing how each category contributes to the final score

### Example Output
```
[1] AUTHENTICATION & TRANSPORT (Weight: 25%)
    Category Score: 85.0/100
    SPF:
      Status: ✓ CONFIGURED
      Score:  ████████░░ 80/100
      SPF Record Found: v=spf1 include:_spf.google.com ~all
```

## Scoring System

- **85-100**: LOW Risk - Excellent email security posture
- **70-84**: MODERATE-LOW Risk - Good security with minor gaps
- **55-69**: MODERATE Risk - Acceptable but needs improvement
- **40-54**: MODERATE-HIGH Risk - Significant security gaps
- **25-39**: HIGH Risk - Weak security, high phishing risk
- **0-24**: CRITICAL Risk - Severe security deficiencies

## Category Weights

The final score is calculated using weighted contributions:
- Authentication & Transport: **25%**
- Sender & Domain Intelligence: **20%**
- IP/ASN Reputation: **15%**
- URL Intelligence: **20%**
- Attachment Metadata: **10%**
- Behavioral Proxies: **10%**

## Files

- `email_metadata_checker.py` - Main script
- `requirements.txt` - Python dependencies
- `run_email_checker.sh` - Convenience runner script
- `README_EMAIL_CHECKER.md` - This documentation

## Notes

- Some checks require the sender's IP address for full analysis
- URL intelligence requires email body content
- Attachment analysis requires attachment data
- IP geolocation uses free ip-api.com service (rate limited)
- For production use, consider integrating:
  - VirusTotal API for hash reputation
  - Paid IP reputation services
  - Full RDAP implementation

## Troubleshooting

### "ModuleNotFoundError: No module named 'dns'"
Make sure you activated the virtual environment:
```bash
source venv/bin/activate
```

### External managed environment error
Don't use system pip. Always use the virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Author

Velura Labs - Internal Prototyping Tool

## License

Internal use only.
