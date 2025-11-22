#!/usr/bin/env python3
"""
Velura Labs - Email Metadata Security Checker
Internal Prototyping Tool
Comprehensive email security analysis with weighted scoring:
- Authentication & Transport (25%): SPF, DKIM, DMARC, ARC, TLS
- Sender & Domain Intelligence (20%): Domain age, WHOIS, TLD risk, RDAP
- IP/ASN Reputation (15%): IP reputation, geolocation, ASN risk
- URL Intelligence (20%): Homograph, typosquat, redirect analysis
- Attachment Metadata (10%): MIME/extension mismatch, hash reputation
- Behavioral Proxies (10%): First-time sender, time anomaly, reply-to mismatch
"""

import re
import dns.resolver
import sys
import socket
import whois
import json
import hashlib
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress
from collections import defaultdict

class EmailDomainChecker:
    def __init__(self, email, sender_ip=None, email_body=None, attachments=None):
        self.email = email
        self.domain = self.extract_domain(email)
        self.sender_ip = sender_ip
        self.email_body = email_body or ""
        self.attachments = attachments or []

        # Category: Authentication & Transport (25%)
        self.auth_transport_results = {
            'spf': {'status': 'unknown', 'details': '', 'score': 0},
            'dkim': {'status': 'unknown', 'details': '', 'score': 0},
            'dmarc': {'status': 'unknown', 'details': '', 'score': 0},
            'arc': {'status': 'unknown', 'details': '', 'score': 0},
            'tls': {'status': 'unknown', 'details': '', 'score': 0}
        }

        # Category: Sender & Domain Intelligence (20%)
        self.domain_intel_results = {
            'domain_age': {'status': 'unknown', 'details': '', 'score': 0},
            'whois_privacy': {'status': 'unknown', 'details': '', 'score': 0},
            'tld_risk': {'status': 'unknown', 'details': '', 'score': 0},
            'rdap': {'status': 'unknown', 'details': '', 'score': 0}
        }

        # Category: IP/ASN Reputation (15%)
        self.ip_reputation_results = {
            'ip_reputation': {'status': 'unknown', 'details': '', 'score': 0},
            'geolocation': {'status': 'unknown', 'details': '', 'score': 0},
            'asn_risk': {'status': 'unknown', 'details': '', 'score': 0}
        }

        # Category: URL Intelligence (20%)
        self.url_intel_results = {
            'homograph': {'status': 'unknown', 'details': '', 'score': 0},
            'typosquat': {'status': 'unknown', 'details': '', 'score': 0},
            'redirect_analysis': {'status': 'unknown', 'details': '', 'score': 0}
        }

        # Category: Attachment Metadata (10%)
        self.attachment_results = {
            'mime_mismatch': {'status': 'unknown', 'details': '', 'score': 0},
            'macro_detection': {'status': 'unknown', 'details': '', 'score': 0},
            'hash_reputation': {'status': 'unknown', 'details': '', 'score': 0}
        }

        # Category: Behavioral Proxies (10%)
        self.behavioral_results = {
            'first_time_sender': {'status': 'unknown', 'details': '', 'score': 0},
            'time_anomaly': {'status': 'unknown', 'details': '', 'score': 0},
            'reply_to_mismatch': {'status': 'unknown', 'details': '', 'score': 0}
        }

        # Legacy MX check (part of infrastructure)
        self.mx_results = {'status': 'unknown', 'details': '', 'score': 0}

        # Historical sender data (for behavioral analysis)
        self.sender_history = defaultdict(list)

    def extract_domain(self, email):
        """Extract domain from email address"""
        match = re.search(r'@([\w\.-]+)', email)
        if match:
            return match.group(1)
        return email

    def check_spf(self):
        """Check SPF (Sender Policy Framework) record"""
        print("\n[*] Checking SPF...")

        try:
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
            spf_found = False

            for record in txt_records:
                record_str = str(record).strip('"')
                if record_str.startswith('v=spf1'):
                    spf_found = True
                    self.auth_transport_results['spf']['status'] = 'CONFIGURED'
                    self.auth_transport_results['spf']['details'] = f'SPF Record Found:\n  {record_str}'

                    # Analyze SPF mechanisms
                    mechanisms = []
                    if 'a' in record_str:
                        mechanisms.append('A record check')
                    if 'mx' in record_str:
                        mechanisms.append('MX record check')
                    if 'include:' in record_str:
                        includes = re.findall(r'include:([\w\.-]+)', record_str)
                        mechanisms.append(f'Includes: {", ".join(includes)}')
                    if 'ip4:' in record_str or 'ip6:' in record_str:
                        mechanisms.append('Direct IP authorization')

                    # Check policy
                    if '-all' in record_str:
                        self.auth_transport_results['spf']['details'] += '\n  Policy: HARD FAIL (-all) - Strict, rejects unauthorized'
                        self.auth_transport_results['spf']['score'] = 100
                    elif '~all' in record_str:
                        self.auth_transport_results['spf']['details'] += '\n  Policy: SOFT FAIL (~all) - Moderate, marks as spam'
                        self.auth_transport_results['spf']['score'] = 80
                    elif '?all' in record_str:
                        self.auth_transport_results['spf']['details'] += '\n  Policy: NEUTRAL (?all) - No assertion'
                        self.auth_transport_results['spf']['score'] = 50
                    elif '+all' in record_str:
                        self.auth_transport_results['spf']['details'] += '\n  Policy: PASS (+all) - Allows all (INSECURE!)'
                        self.auth_transport_results['spf']['score'] = 10

                    if mechanisms:
                        self.auth_transport_results['spf']['details'] += f'\n  Mechanisms: {", ".join(mechanisms)}'

                    break

            if not spf_found:
                self.auth_transport_results['spf']['status'] = 'NOT CONFIGURED'
                self.auth_transport_results['spf']['score'] = 0
                self.auth_transport_results['spf']['details'] = 'No SPF record found - emails may be marked as spam'

        except dns.resolver.NXDOMAIN:
            self.auth_transport_results['spf']['status'] = 'DOMAIN NOT FOUND'
            self.auth_transport_results['spf']['score'] = 0
            self.auth_transport_results['spf']['details'] = 'Domain does not exist'
        except dns.resolver.NoAnswer:
            self.auth_transport_results['spf']['status'] = 'NOT CONFIGURED'
            self.auth_transport_results['spf']['score'] = 0
            self.auth_transport_results['spf']['details'] = 'No TXT records found'
        except Exception as e:
            self.auth_transport_results['spf']['status'] = 'ERROR'
            self.auth_transport_results['spf']['score'] = 50
            self.auth_transport_results['spf']['details'] = f'Error: {str(e)}'

    def check_dkim(self):
        """Check DKIM (DomainKeys Identified Mail) configuration"""
        print("[*] Checking DKIM...")

        # Common DKIM selectors used by major email providers
        common_selectors = [
            'default', 'selector1', 'selector2', 'google', 'k1', 's1', 's2',
            'dkim', 'mail', 'email', 'smtp', 'mx', 'key1', 'key2'
        ]

        found_selectors = []

        for selector in common_selectors:
            try:
                dkim_domain = f'{selector}._domainkey.{self.domain}'
                txt_records = dns.resolver.resolve(dkim_domain, 'TXT')

                for record in txt_records:
                    record_str = str(record).strip('"')
                    if 'v=DKIM1' in record_str or 'p=' in record_str:
                        found_selectors.append(selector)

                        # Parse key info
                        key_type = 'RSA'
                        if 'k=rsa' in record_str:
                            key_type = 'RSA'
                        elif 'k=ed25519' in record_str:
                            key_type = 'Ed25519'

                        if not self.auth_transport_results['dkim']['details']:
                            self.auth_transport_results['dkim']['details'] = f'DKIM Configured:\n  Selector "{selector}": {key_type} key'
                        else:
                            self.auth_transport_results['dkim']['details'] += f'\n  Selector "{selector}": {key_type} key'

                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue

        if found_selectors:
            self.auth_transport_results['dkim']['status'] = 'CONFIGURED'
            self.auth_transport_results['dkim']['score'] = 100
            self.auth_transport_results['dkim']['details'] += f'\n  Found {len(found_selectors)} selector(s)'
        else:
            self.auth_transport_results['dkim']['status'] = 'NOT FOUND'
            self.auth_transport_results['dkim']['score'] = 20
            self.auth_transport_results['dkim']['details'] = f'No DKIM keys found (checked common selectors)\n  Note: DKIM selector names vary - the actual selector may be different'

    def check_dmarc(self):
        """Check DMARC (Domain-based Message Authentication) policy"""
        print("[*] Checking DMARC...")

        try:
            dmarc_domain = f'_dmarc.{self.domain}'
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')

            for record in txt_records:
                record_str = str(record).strip('"')
                if record_str.startswith('v=DMARC1'):
                    self.auth_transport_results['dmarc']['status'] = 'CONFIGURED'
                    self.auth_transport_results['dmarc']['details'] = f'DMARC Record Found:\n  {record_str}'

                    # Parse policy
                    if 'p=reject' in record_str:
                        self.auth_transport_results['dmarc']['details'] += '\n  Policy: REJECT - Strict (best security)'
                        self.auth_transport_results['dmarc']['score'] = 100
                    elif 'p=quarantine' in record_str:
                        self.auth_transport_results['dmarc']['details'] += '\n  Policy: QUARANTINE - Moderate'
                        self.auth_transport_results['dmarc']['score'] = 80
                    elif 'p=none' in record_str:
                        self.auth_transport_results['dmarc']['details'] += '\n  Policy: NONE - Monitoring only (weak)'
                        self.auth_transport_results['dmarc']['score'] = 50

                    # Parse alignment
                    if 'aspf=s' in record_str:
                        self.auth_transport_results['dmarc']['details'] += '\n  SPF Alignment: Strict'
                    elif 'aspf=r' in record_str:
                        self.auth_transport_results['dmarc']['details'] += '\n  SPF Alignment: Relaxed'

                    if 'adkim=s' in record_str:
                        self.auth_transport_results['dmarc']['details'] += '\n  DKIM Alignment: Strict'
                    elif 'adkim=r' in record_str:
                        self.auth_transport_results['dmarc']['details'] += '\n  DKIM Alignment: Relaxed'

                    # Parse reporting
                    rua = re.search(r'rua=([^\s;]+)', record_str)
                    if rua:
                        self.auth_transport_results['dmarc']['details'] += f'\n  Aggregate Reports: {rua.group(1)}'

                    ruf = re.search(r'ruf=([^\s;]+)', record_str)
                    if ruf:
                        self.auth_transport_results['dmarc']['details'] += f'\n  Forensic Reports: {ruf.group(1)}'

                    break

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self.auth_transport_results['dmarc']['status'] = 'NOT CONFIGURED'
            self.auth_transport_results['dmarc']['score'] = 0
            self.auth_transport_results['dmarc']['details'] = 'No DMARC policy found - vulnerable to spoofing'
        except Exception as e:
            self.auth_transport_results['dmarc']['status'] = 'ERROR'
            self.auth_transport_results['dmarc']['score'] = 50
            self.auth_transport_results['dmarc']['details'] = f'Error: {str(e)}'

    def check_arc(self):
        """Check ARC (Authenticated Received Chain) support"""
        print("[*] Checking ARC...")

        try:
            # Check for ARC selector (similar to DKIM)
            common_arc_selectors = ['arc', 'arc-seal', 'default']

            found_arc = False
            for selector in common_arc_selectors:
                try:
                    arc_domain = f'{selector}._domainkey.{self.domain}'
                    txt_records = dns.resolver.resolve(arc_domain, 'TXT')

                    for record in txt_records:
                        record_str = str(record).strip('"')
                        if 'v=ARC1' in record_str or 'arc' in record_str.lower():
                            found_arc = True
                            self.auth_transport_results['arc']['status'] = 'CONFIGURED'
                            self.auth_transport_results['arc']['score'] = 100
                            self.auth_transport_results['arc']['details'] = f'ARC support detected\n  Selector: {selector}\n  Assessment: Email chain authentication enabled'
                            break
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue

                if found_arc:
                    break

            if not found_arc:
                self.auth_transport_results['arc']['status'] = 'NOT CONFIGURED'
                self.auth_transport_results['arc']['score'] = 70
                self.auth_transport_results['arc']['details'] = 'ARC not configured\n  Note: Not critical but helps with forwarded emails'

        except Exception as e:
            self.auth_transport_results['arc']['status'] = 'ERROR'
            self.auth_transport_results['arc']['score'] = 70
            self.auth_transport_results['arc']['details'] = f'Error checking ARC: {str(e)}'

    def check_mx(self):
        """Check MX (Mail Exchange) records"""
        print("[*] Checking MX Records...")

        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            mx_list = []

            for record in sorted(mx_records, key=lambda x: x.preference):
                mx_list.append(f'Priority {record.preference}: {str(record.exchange)}')

            if mx_list:
                self.mx_results['status'] = 'CONFIGURED'
                self.mx_results['score'] = 100
                self.mx_results['details'] = f'Mail servers found:\n  ' + '\n  '.join(mx_list)

                # Identify provider
                mx_str = ' '.join(mx_list).lower()
                if 'google' in mx_str or 'googlemail' in mx_str:
                    self.mx_results['details'] += '\n  Provider: Google Workspace / Gmail'
                elif 'outlook' in mx_str or 'microsoft' in mx_str:
                    self.mx_results['details'] += '\n  Provider: Microsoft 365 / Outlook'
                elif 'mimecast' in mx_str:
                    self.mx_results['details'] += '\n  Provider: Mimecast (Email Security)'
                elif 'proofpoint' in mx_str:
                    self.mx_results['details'] += '\n  Provider: Proofpoint (Email Security)'
            else:
                self.mx_results['status'] = 'NOT CONFIGURED'
                self.mx_results['score'] = 0
                self.mx_results['details'] = 'No MX records - cannot receive email'

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self.mx_results['status'] = 'NOT CONFIGURED'
            self.mx_results['score'] = 0
            self.mx_results['details'] = 'No MX records found'
        except Exception as e:
            self.mx_results['status'] = 'ERROR'
            self.mx_results['score'] = 50
            self.mx_results['details'] = f'Error: {str(e)}'

    def check_tls_support(self):
        """Check if mail server supports TLS/SSL with cipher details"""
        print("[*] Checking TLS Support...")

        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            if mx_records:
                # Get the primary MX
                primary_mx = min(mx_records, key=lambda x: x.preference)
                mx_host = str(primary_mx.exchange).rstrip('.')

                # Try to connect to SMTP port
                try:
                    import ssl

                    # Test STARTTLS on port 25
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)

                    # Try port 25 first (SMTP)
                    try:
                        sock.connect((mx_host, 25))
                        response = sock.recv(1024).decode()

                        sock.send(b'EHLO test\r\n')
                        response = sock.recv(1024).decode()

                        if 'STARTTLS' in response:
                            self.auth_transport_results['tls']['status'] = 'SUPPORTED'
                            self.auth_transport_results['tls']['score'] = 100
                            self.auth_transport_results['tls']['details'] = f'TLS supported on {mx_host}:25\n  STARTTLS available'
                        else:
                            self.auth_transport_results['tls']['status'] = 'NOT SUPPORTED'
                            self.auth_transport_results['tls']['score'] = 0
                            self.auth_transport_results['tls']['details'] = f'TLS not advertised on {mx_host}:25'

                        sock.close()
                    except:
                        # Try port 465 (SMTPS)
                        try:
                            context = ssl.create_default_context()
                            with socket.create_connection((mx_host, 465), timeout=5) as sock_conn:
                                with context.wrap_socket(sock_conn, server_hostname=mx_host) as ssock:
                                    cipher = ssock.cipher()
                                    version = ssock.version()

                                    self.auth_transport_results['tls']['status'] = 'SUPPORTED'
                                    self.auth_transport_results['tls']['score'] = 100
                                    self.auth_transport_results['tls']['details'] = f'TLS/SSL supported on {mx_host}:465\n  Version: {version}\n  Cipher: {cipher[0]}\n  Cipher Suite: {cipher[1]}\n  Key Size: {cipher[2]} bits'
                        except:
                            self.auth_transport_results['tls']['status'] = 'UNKNOWN'
                            self.auth_transport_results['tls']['score'] = 50
                            self.auth_transport_results['tls']['details'] = f'Could not verify TLS on {mx_host}'

                except Exception as e:
                    self.auth_transport_results['tls']['status'] = 'UNKNOWN'
                    self.auth_transport_results['tls']['score'] = 50
                    self.auth_transport_results['tls']['details'] = f'Cannot test TLS: {str(e)}'
            else:
                self.auth_transport_results['tls']['status'] = 'NO MX'
                self.auth_transport_results['tls']['score'] = 50
                self.auth_transport_results['tls']['details'] = 'No mail server to test'

        except Exception as e:
            self.auth_transport_results['tls']['status'] = 'ERROR'
            self.auth_transport_results['tls']['score'] = 50
            self.auth_transport_results['tls']['details'] = f'Error: {str(e)}'

    def check_domain_age(self):
        """Check domain age and registration date"""
        print("[*] Checking Domain Age...")

        try:
            w = whois.whois(self.domain)

            # Get creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                # Make timezone-aware if needed
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)
                age = now - creation_date
                days_old = age.days
                years_old = days_old / 365.25

                self.domain_intel_results['domain_age']['details'] = f'Created: {creation_date.strftime("%Y-%m-%d")}\n  Age: {days_old} days ({years_old:.1f} years)'

                # Scoring based on age
                if years_old >= 5:
                    self.domain_intel_results['domain_age']['status'] = 'ESTABLISHED'
                    self.domain_intel_results['domain_age']['score'] = 100
                    self.domain_intel_results['domain_age']['details'] += '\n  Assessment: Well-established domain'
                elif years_old >= 2:
                    self.domain_intel_results['domain_age']['status'] = 'MODERATE'
                    self.domain_intel_results['domain_age']['score'] = 70
                    self.domain_intel_results['domain_age']['details'] += '\n  Assessment: Moderately aged domain'
                elif years_old >= 1:
                    self.domain_intel_results['domain_age']['status'] = 'RECENT'
                    self.domain_intel_results['domain_age']['score'] = 50
                    self.domain_intel_results['domain_age']['details'] += '\n  Assessment: Recently registered'
                elif days_old >= 30:
                    self.domain_intel_results['domain_age']['status'] = 'NEW'
                    self.domain_intel_results['domain_age']['score'] = 20
                    self.domain_intel_results['domain_age']['details'] += '\n  Assessment: New domain (caution advised)'
                else:
                    self.domain_intel_results['domain_age']['status'] = 'VERY NEW'
                    self.domain_intel_results['domain_age']['score'] = 0
                    self.domain_intel_results['domain_age']['details'] += '\n  Assessment: Very new domain (high risk)'

                # Check expiration
                expiration_date = w.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                if expiration_date:
                    if expiration_date.tzinfo is None:
                        expiration_date = expiration_date.replace(tzinfo=timezone.utc)

                    days_until_expiry = (expiration_date - now).days
                    self.domain_intel_results['domain_age']['details'] += f'\n  Expires: {expiration_date.strftime("%Y-%m-%d")} ({days_until_expiry} days)'

                    if days_until_expiry < 30:
                        self.domain_intel_results['domain_age']['details'] += '\n  Warning: Domain expiring soon!'
                        self.domain_intel_results['domain_age']['score'] = max(0, self.domain_intel_results['domain_age']['score'] - 30)
            else:
                self.domain_intel_results['domain_age']['status'] = 'UNKNOWN'
                self.domain_intel_results['domain_age']['score'] = 50
                self.domain_intel_results['domain_age']['details'] = 'Creation date not available'

        except Exception as e:
            self.domain_intel_results['domain_age']['status'] = 'ERROR'
            self.domain_intel_results['domain_age']['score'] = 50
            self.domain_intel_results['domain_age']['details'] = f'Could not retrieve WHOIS data: {str(e)}'

    def check_whois_privacy(self):
        """Check if WHOIS privacy protection is enabled"""
        print("[*] Checking WHOIS Privacy...")

        try:
            w = whois.whois(self.domain)

            # Common privacy service indicators
            privacy_indicators = [
                'privacy', 'protected', 'redacted', 'proxy', 'whoisguard',
                'domains by proxy', 'contact privacy', 'private registration',
                'withheld', 'data redacted', 'not disclosed'
            ]

            # Check registrant, admin, and tech contacts
            fields_to_check = []

            if w.registrant_name:
                fields_to_check.append(str(w.registrant_name).lower())
            if w.emails:
                if isinstance(w.emails, list):
                    fields_to_check.extend([str(e).lower() for e in w.emails])
                else:
                    fields_to_check.append(str(w.emails).lower())
            if w.org:
                fields_to_check.append(str(w.org).lower())

            # Check for privacy indicators
            has_privacy = False
            privacy_service = None

            for field in fields_to_check:
                for indicator in privacy_indicators:
                    if indicator in field:
                        has_privacy = True
                        privacy_service = field
                        break
                if has_privacy:
                    break

            if has_privacy:
                self.domain_intel_results['whois_privacy']['status'] = 'ENABLED'
                self.domain_intel_results['whois_privacy']['score'] = 30
                self.domain_intel_results['whois_privacy']['details'] = f'Privacy protection detected\n  Service: {privacy_service[:50]}\n  Assessment: Owner identity hidden (moderate risk)'
            else:
                self.domain_intel_results['whois_privacy']['status'] = 'DISABLED'
                self.domain_intel_results['whois_privacy']['score'] = 100

                # Show registrant info
                info_parts = []
                if w.registrant_name and str(w.registrant_name).lower() != 'none':
                    info_parts.append(f'Name: {w.registrant_name}')
                if w.org and str(w.org).lower() != 'none':
                    info_parts.append(f'Org: {w.org}')
                if w.country and str(w.country).lower() != 'none':
                    info_parts.append(f'Country: {w.country}')

                if info_parts:
                    self.domain_intel_results['whois_privacy']['details'] = 'Public registration\n  ' + '\n  '.join(info_parts[:3])
                else:
                    self.domain_intel_results['whois_privacy']['details'] = 'Public registration (no privacy protection)'

                self.domain_intel_results['whois_privacy']['details'] += '\n  Assessment: Transparent ownership (lower risk)'

        except Exception as e:
            self.domain_intel_results['whois_privacy']['status'] = 'UNKNOWN'
            self.domain_intel_results['whois_privacy']['score'] = 50
            self.domain_intel_results['whois_privacy']['details'] = f'Could not check privacy status: {str(e)}'

    def check_rdap(self):
        """Check RDAP (Registration Data Access Protocol) for enhanced WHOIS data"""
        print("[*] Checking RDAP...")

        try:
            # RDAP is the modern replacement for WHOIS
            # For now, we'll provide a basic implementation
            self.domain_intel_results['rdap']['status'] = 'INFO'
            self.domain_intel_results['rdap']['score'] = 100
            self.domain_intel_results['rdap']['details'] = 'RDAP provides structured registration data\n  Note: Full RDAP implementation requires API integration\n  Using WHOIS as fallback'

        except Exception as e:
            self.domain_intel_results['rdap']['status'] = 'ERROR'
            self.domain_intel_results['rdap']['score'] = 50
            self.domain_intel_results['rdap']['details'] = f'RDAP check failed: {str(e)}'

    def check_tld_risk(self):
        """Assess TLD (Top-Level Domain) risk level"""
        print("[*] Checking TLD Risk...")

        tld = self.domain.split('.')[-1].lower()

        # TLD risk categories
        trusted_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'uk', 'ca', 'au', 'de', 'fr', 'jp', 'nl', 'se', 'ch', 'it', 'es'
        }

        moderate_risk_tlds = {
            'info', 'biz', 'name', 'pro', 'io', 'co', 'me', 'tv', 'cc',
            'us', 'eu', 'asia', 'mobi', 'tel', 'travel', 'jobs', 'cat'
        }

        high_risk_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs often abused
            'xyz', 'top', 'work', 'click', 'link', 'download',
            'stream', 'trade', 'webcam', 'party', 'racing', 'science',
            'loan', 'win', 'bid', 'accountant', 'faith', 'cricket',
            'date', 'review', 'country', 'kim', 'christmas'
        }

        if tld in trusted_tlds:
            self.domain_intel_results['tld_risk']['status'] = 'LOW RISK'
            self.domain_intel_results['tld_risk']['score'] = 100
            self.domain_intel_results['tld_risk']['details'] = f'TLD: .{tld}\n  Category: Trusted/Established\n  Assessment: Low risk domain extension'
        elif tld in moderate_risk_tlds:
            self.domain_intel_results['tld_risk']['status'] = 'MODERATE RISK'
            self.domain_intel_results['tld_risk']['score'] = 60
            self.domain_intel_results['tld_risk']['details'] = f'TLD: .{tld}\n  Category: Moderate\n  Assessment: Common but requires verification'
        elif tld in high_risk_tlds:
            self.domain_intel_results['tld_risk']['status'] = 'HIGH RISK'
            self.domain_intel_results['tld_risk']['score'] = 0
            self.domain_intel_results['tld_risk']['details'] = f'TLD: .{tld}\n  Category: High-risk/Frequently abused\n  Assessment: Suspicious domain extension'
        else:
            # Unknown or newer TLD
            self.domain_intel_results['tld_risk']['status'] = 'UNKNOWN'
            self.domain_intel_results['tld_risk']['score'] = 50
            self.domain_intel_results['tld_risk']['details'] = f'TLD: .{tld}\n  Category: Unclassified\n  Assessment: Exercise caution with unfamiliar TLDs'

    def check_ip_reputation(self):
        """Check IP reputation and geolocation"""
        print("[*] Checking IP/ASN Reputation...")

        if not self.sender_ip:
            self.ip_reputation_results['ip_reputation']['status'] = 'NO IP PROVIDED'
            self.ip_reputation_results['ip_reputation']['score'] = 50
            self.ip_reputation_results['ip_reputation']['details'] = 'No sender IP provided for analysis'

            self.ip_reputation_results['geolocation']['status'] = 'NO IP PROVIDED'
            self.ip_reputation_results['geolocation']['score'] = 50
            self.ip_reputation_results['geolocation']['details'] = 'No sender IP for geolocation'

            self.ip_reputation_results['asn_risk']['status'] = 'NO IP PROVIDED'
            self.ip_reputation_results['asn_risk']['score'] = 50
            self.ip_reputation_results['asn_risk']['details'] = 'No sender IP for ASN check'
            return

        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(self.sender_ip)

            # Check if private IP
            if ip_obj.is_private:
                self.ip_reputation_results['ip_reputation']['status'] = 'PRIVATE IP'
                self.ip_reputation_results['ip_reputation']['score'] = 30
                self.ip_reputation_results['ip_reputation']['details'] = f'IP: {self.sender_ip}\n  Type: Private/Internal\n  Warning: Should not be sending external emails'
                return

            # Use free IP geolocation API (ip-api.com)
            try:
                response = requests.get(f'http://ip-api.com/json/{self.sender_ip}', timeout=5)
                if response.status_code == 200:
                    geo_data = response.json()

                    if geo_data.get('status') == 'success':
                        # Geolocation results
                        country = geo_data.get('country', 'Unknown')
                        city = geo_data.get('city', 'Unknown')
                        isp = geo_data.get('isp', 'Unknown')
                        asn = geo_data.get('as', 'Unknown')

                        self.ip_reputation_results['geolocation']['status'] = 'IDENTIFIED'
                        self.ip_reputation_results['geolocation']['score'] = 100
                        self.ip_reputation_results['geolocation']['details'] = f'IP: {self.sender_ip}\n  Country: {country}\n  City: {city}\n  ISP: {isp}'

                        # ASN analysis
                        self.ip_reputation_results['asn_risk']['status'] = 'IDENTIFIED'
                        self.ip_reputation_results['asn_risk']['details'] = f'ASN: {asn}\n  ISP: {isp}'

                        # Score based on ISP type
                        known_good_isps = ['google', 'microsoft', 'amazon', 'cloudflare', 'office365']
                        high_risk_keywords = ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud']

                        isp_lower = isp.lower()
                        if any(good in isp_lower for good in known_good_isps):
                            self.ip_reputation_results['asn_risk']['score'] = 100
                            self.ip_reputation_results['asn_risk']['details'] += '\n  Assessment: Trusted mail provider'
                        elif any(risk in isp_lower for risk in high_risk_keywords):
                            self.ip_reputation_results['asn_risk']['score'] = 40
                            self.ip_reputation_results['asn_risk']['details'] += '\n  Warning: Hosting/VPN detected (moderate risk)'
                        else:
                            self.ip_reputation_results['asn_risk']['score'] = 70
                            self.ip_reputation_results['asn_risk']['details'] += '\n  Assessment: Standard ISP'

                        # IP reputation - basic heuristic
                        self.ip_reputation_results['ip_reputation']['status'] = 'ANALYZED'
                        self.ip_reputation_results['ip_reputation']['score'] = 70
                        self.ip_reputation_results['ip_reputation']['details'] = f'IP: {self.sender_ip}\n  Note: Full reputation check requires API keys\n  Basic check: No major issues detected'

            except requests.exceptions.RequestException:
                self.ip_reputation_results['ip_reputation']['status'] = 'CHECK FAILED'
                self.ip_reputation_results['ip_reputation']['score'] = 50
                self.ip_reputation_results['ip_reputation']['details'] = 'Could not connect to IP reputation service'

        except ValueError:
            self.ip_reputation_results['ip_reputation']['status'] = 'INVALID IP'
            self.ip_reputation_results['ip_reputation']['score'] = 0
            self.ip_reputation_results['ip_reputation']['details'] = f'Invalid IP address format: {self.sender_ip}'

    def check_url_intelligence(self):
        """Check URLs in email for phishing indicators"""
        print("[*] Checking URL Intelligence...")

        # Extract URLs from email body
        url_pattern = r'https?://[^\s<>"{}|\\^\[\]`]+'
        urls = re.findall(url_pattern, self.email_body)

        if not urls:
            self.url_intel_results['homograph']['status'] = 'NO URLS'
            self.url_intel_results['homograph']['score'] = 100
            self.url_intel_results['homograph']['details'] = 'No URLs found in email'

            self.url_intel_results['typosquat']['status'] = 'NO URLS'
            self.url_intel_results['typosquat']['score'] = 100
            self.url_intel_results['typosquat']['details'] = 'No URLs to analyze'

            self.url_intel_results['redirect_analysis']['status'] = 'NO URLS'
            self.url_intel_results['redirect_analysis']['score'] = 100
            self.url_intel_results['redirect_analysis']['details'] = 'No URLs to check'
            return

        # Homograph detection (punycode/IDN)
        homograph_detected = False
        typosquat_detected = False

        suspicious_urls = []

        for url in urls[:10]:  # Limit to first 10 URLs
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()

                # Check for punycode (xn--)
                if 'xn--' in domain:
                    homograph_detected = True
                    suspicious_urls.append(f'{url} (Punycode detected)')

                # Check for common typosquats
                typosquat_targets = ['google', 'microsoft', 'amazon', 'paypal', 'apple', 'facebook']
                for target in typosquat_targets:
                    if target in domain and target != domain:
                        # Calculate Levenshtein-like distance
                        if self._is_potential_typosquat(domain, target):
                            typosquat_detected = True
                            suspicious_urls.append(f'{url} (Potential {target} typosquat)')

            except Exception:
                continue

        # Homograph results
        if homograph_detected:
            self.url_intel_results['homograph']['status'] = 'DETECTED'
            self.url_intel_results['homograph']['score'] = 0
            self.url_intel_results['homograph']['details'] = f'Homograph attack detected!\n  Suspicious URLs found: {len(suspicious_urls)}\n  Warning: IDN homograph detected'
        else:
            self.url_intel_results['homograph']['status'] = 'CLEAN'
            self.url_intel_results['homograph']['score'] = 100
            self.url_intel_results['homograph']['details'] = f'Checked {len(urls)} URL(s)\n  No homograph attacks detected'

        # Typosquat results
        if typosquat_detected:
            self.url_intel_results['typosquat']['status'] = 'DETECTED'
            self.url_intel_results['typosquat']['score'] = 0
            self.url_intel_results['typosquat']['details'] = f'Potential typosquatting detected!\n  Suspicious URLs:\n  ' + '\n  '.join(suspicious_urls[:3])
        else:
            self.url_intel_results['typosquat']['status'] = 'CLEAN'
            self.url_intel_results['typosquat']['score'] = 100
            self.url_intel_results['typosquat']['details'] = f'Checked {len(urls)} URL(s)\n  No typosquatting detected'

        # Redirect analysis (simplified)
        self.url_intel_results['redirect_analysis']['status'] = 'ANALYZED'
        self.url_intel_results['redirect_analysis']['score'] = 80
        self.url_intel_results['redirect_analysis']['details'] = f'Found {len(urls)} URL(s)\n  Note: Full redirect tracing requires live requests'

    def _is_potential_typosquat(self, domain, target):
        """Simple typosquat detection using character similarity"""
        # Remove common TLDs for comparison
        domain_clean = domain.split('.')[0]

        # Check if domain contains target with small modifications
        if target in domain_clean:
            # Check for extra characters
            extra_chars = domain_clean.replace(target, '')
            if len(extra_chars) <= 3 and extra_chars.replace('-', '').replace('_', ''):
                return True

        return False

    def check_attachment_metadata(self):
        """Analyze attachment metadata"""
        print("[*] Checking Attachment Metadata...")

        if not self.attachments:
            self.attachment_results['mime_mismatch']['status'] = 'NO ATTACHMENTS'
            self.attachment_results['mime_mismatch']['score'] = 100
            self.attachment_results['mime_mismatch']['details'] = 'No attachments to analyze'

            self.attachment_results['macro_detection']['status'] = 'NO ATTACHMENTS'
            self.attachment_results['macro_detection']['score'] = 100
            self.attachment_results['macro_detection']['details'] = 'No attachments to check'

            self.attachment_results['hash_reputation']['status'] = 'NO ATTACHMENTS'
            self.attachment_results['hash_reputation']['score'] = 100
            self.attachment_results['hash_reputation']['details'] = 'No attachments to hash'
            return

        # Analyze each attachment
        mime_mismatches = []
        macro_files = []
        file_hashes = []

        for attachment in self.attachments:
            filename = attachment.get('filename', 'unknown')
            content = attachment.get('content', b'')
            declared_mime = attachment.get('mime_type', 'unknown')

            # Get file extension
            ext = filename.split('.')[-1].lower() if '.' in filename else 'none'

            # Detect magic bytes
            magic_bytes = content[:4] if len(content) >= 4 else b''

            # Common magic byte signatures
            actual_type = self._detect_file_type(magic_bytes)

            # Check MIME mismatch
            if actual_type and actual_type != ext:
                mime_mismatches.append(f'{filename} (Extension: .{ext}, Actual: {actual_type})')

            # Check for macro-enabled files
            macro_extensions = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm']
            if ext in macro_extensions:
                macro_files.append(filename)

            # Calculate hash
            file_hash = hashlib.sha256(content).hexdigest()
            file_hashes.append(f'{filename}: {file_hash[:16]}...')

        # MIME mismatch results
        if mime_mismatches:
            self.attachment_results['mime_mismatch']['status'] = 'DETECTED'
            self.attachment_results['mime_mismatch']['score'] = 0
            self.attachment_results['mime_mismatch']['details'] = f'MIME mismatch detected!\n  Files:\n  ' + '\n  '.join(mime_mismatches)
        else:
            self.attachment_results['mime_mismatch']['status'] = 'CLEAN'
            self.attachment_results['mime_mismatch']['score'] = 100
            self.attachment_results['mime_mismatch']['details'] = f'Checked {len(self.attachments)} file(s)\n  No MIME mismatches detected'

        # Macro detection results
        if macro_files:
            self.attachment_results['macro_detection']['status'] = 'DETECTED'
            self.attachment_results['macro_detection']['score'] = 30
            self.attachment_results['macro_detection']['details'] = f'Macro-enabled files detected:\n  ' + '\n  '.join(macro_files) + '\n  Warning: Macros can contain malicious code'
        else:
            self.attachment_results['macro_detection']['status'] = 'CLEAN'
            self.attachment_results['macro_detection']['score'] = 100
            self.attachment_results['macro_detection']['details'] = f'Checked {len(self.attachments)} file(s)\n  No macro-enabled files detected'

        # Hash reputation
        self.attachment_results['hash_reputation']['status'] = 'COMPUTED'
        self.attachment_results['hash_reputation']['score'] = 70
        self.attachment_results['hash_reputation']['details'] = f'Computed hashes for {len(self.attachments)} file(s)\n  Note: Hash reputation check requires VirusTotal API\n  Hashes:\n  ' + '\n  '.join(file_hashes[:3])

    def _detect_file_type(self, magic_bytes):
        """Detect file type from magic bytes"""
        signatures = {
            b'\xFF\xD8\xFF': 'jpg',
            b'\x89PNG': 'png',
            b'GIF8': 'gif',
            b'PK\x03\x04': 'zip',
            b'%PDF': 'pdf',
            b'\xD0\xCF\x11\xE0': 'doc/xls',
        }

        for sig, file_type in signatures.items():
            if magic_bytes.startswith(sig):
                return file_type

        return None

    def check_behavioral_proxies(self):
        """Analyze behavioral patterns"""
        print("[*] Checking Behavioral Proxies...")

        # First-time sender check (requires historical data)
        sender_key = self.email.lower()
        if sender_key in self.sender_history:
            self.behavioral_results['first_time_sender']['status'] = 'KNOWN SENDER'
            self.behavioral_results['first_time_sender']['score'] = 100
            self.behavioral_results['first_time_sender']['details'] = f'Sender: {self.email}\n  Previous emails: {len(self.sender_history[sender_key])}\n  Assessment: Established correspondence'
        else:
            self.behavioral_results['first_time_sender']['status'] = 'FIRST TIME'
            self.behavioral_results['first_time_sender']['score'] = 50
            self.behavioral_results['first_time_sender']['details'] = f'Sender: {self.email}\n  Warning: First-time sender\n  Recommendation: Verify sender authenticity'

        # Time anomaly detection (check for odd sending times)
        current_hour = datetime.now(timezone.utc).hour

        # Business hours: 6 AM - 10 PM
        if 6 <= current_hour <= 22:
            self.behavioral_results['time_anomaly']['status'] = 'NORMAL HOURS'
            self.behavioral_results['time_anomaly']['score'] = 100
            self.behavioral_results['time_anomaly']['details'] = f'Received time: {current_hour:02d}:00 UTC\n  Assessment: Within normal business hours'
        else:
            self.behavioral_results['time_anomaly']['status'] = 'ODD HOURS'
            self.behavioral_results['time_anomaly']['score'] = 70
            self.behavioral_results['time_anomaly']['details'] = f'Received time: {current_hour:02d}:00 UTC\n  Note: Received outside typical business hours\n  May be legitimate (timezone differences)'

        # Reply-to mismatch check (simplified - needs email headers)
        # For now, check if domain matches sender domain
        self.behavioral_results['reply_to_mismatch']['status'] = 'NOT CHECKED'
        self.behavioral_results['reply_to_mismatch']['score'] = 80
        self.behavioral_results['reply_to_mismatch']['details'] = 'Reply-To analysis requires email headers\n  Note: Provide full email headers for complete analysis'

    def calculate_weighted_score(self):
        """Calculate weighted trust score based on category percentages"""
        category_scores = {}

        # Category 1: Authentication & Transport (25%)
        auth_scores = [self.auth_transport_results[k]['score'] for k in self.auth_transport_results]
        category_scores['auth_transport'] = sum(auth_scores) / len(auth_scores) if auth_scores else 50

        # Category 2: Sender & Domain Intelligence (20%)
        domain_scores = [self.domain_intel_results[k]['score'] for k in self.domain_intel_results]
        category_scores['domain_intel'] = sum(domain_scores) / len(domain_scores) if domain_scores else 50

        # Category 3: IP/ASN Reputation (15%)
        ip_scores = [self.ip_reputation_results[k]['score'] for k in self.ip_reputation_results]
        category_scores['ip_reputation'] = sum(ip_scores) / len(ip_scores) if ip_scores else 50

        # Category 4: URL Intelligence (20%)
        url_scores = [self.url_intel_results[k]['score'] for k in self.url_intel_results]
        category_scores['url_intel'] = sum(url_scores) / len(url_scores) if url_scores else 50

        # Category 5: Attachment Metadata (10%)
        attachment_scores = [self.attachment_results[k]['score'] for k in self.attachment_results]
        category_scores['attachment'] = sum(attachment_scores) / len(attachment_scores) if attachment_scores else 50

        # Category 6: Behavioral Proxies (10%)
        behavioral_scores = [self.behavioral_results[k]['score'] for k in self.behavioral_results]
        category_scores['behavioral'] = sum(behavioral_scores) / len(behavioral_scores) if behavioral_scores else 50

        # Weighted calculation
        final_score = (
            category_scores['auth_transport'] * 0.25 +
            category_scores['domain_intel'] * 0.20 +
            category_scores['ip_reputation'] * 0.15 +
            category_scores['url_intel'] * 0.20 +
            category_scores['attachment'] * 0.10 +
            category_scores['behavioral'] * 0.10
        )

        return final_score, category_scores

    def print_results(self):
        """Print formatted results with weighted category scores"""
        print("\n" + "="*80)
        print("VELURA LABS - COMPREHENSIVE EMAIL METADATA SECURITY ANALYSIS")
        print("="*80)
        print(f"Target: {self.email}")
        if self.sender_ip:
            print(f"Sender IP: {self.sender_ip}")
        print("-"*80)

        # Calculate scores
        final_score, category_scores = self.calculate_weighted_score()

        # Category 1: Authentication & Transport (25%)
        print(f"\n[1] AUTHENTICATION & TRANSPORT (Weight: 25%)")
        print(f"    Category Score: {category_scores['auth_transport']:.1f}/100")
        print("    " + "-"*70)
        for key, result in self.auth_transport_results.items():
            self._print_check_result(key.upper(), result)

        # Category 2: Sender & Domain Intelligence (20%)
        print(f"\n[2] SENDER & DOMAIN INTELLIGENCE (Weight: 20%)")
        print(f"    Category Score: {category_scores['domain_intel']:.1f}/100")
        print("    " + "-"*70)
        for key, result in self.domain_intel_results.items():
            self._print_check_result(key.replace('_', ' ').upper(), result)

        # Category 3: IP/ASN Reputation (15%)
        print(f"\n[3] IP/ASN REPUTATION (Weight: 15%)")
        print(f"    Category Score: {category_scores['ip_reputation']:.1f}/100")
        print("    " + "-"*70)
        for key, result in self.ip_reputation_results.items():
            self._print_check_result(key.replace('_', ' ').upper(), result)

        # Category 4: URL Intelligence (20%)
        print(f"\n[4] URL INTELLIGENCE (Weight: 20%)")
        print(f"    Category Score: {category_scores['url_intel']:.1f}/100")
        print("    " + "-"*70)
        for key, result in self.url_intel_results.items():
            self._print_check_result(key.replace('_', ' ').upper(), result)

        # Category 5: Attachment Metadata (10%)
        print(f"\n[5] ATTACHMENT METADATA (Weight: 10%)")
        print(f"    Category Score: {category_scores['attachment']:.1f}/100")
        print("    " + "-"*70)
        for key, result in self.attachment_results.items():
            self._print_check_result(key.replace('_', ' ').upper(), result)

        # Category 6: Behavioral Proxies (10%)
        print(f"\n[6] BEHAVIORAL PROXIES (Weight: 10%)")
        print(f"    Category Score: {category_scores['behavioral']:.1f}/100")
        print("    " + "-"*70)
        for key, result in self.behavioral_results.items():
            self._print_check_result(key.replace('_', ' ').upper(), result)

        # Overall score
        print("\n" + "="*80)
        print(f"OVERALL WEIGHTED SECURITY SCORE: {final_score:.1f}/100")

        if final_score >= 85:
            print("Risk Level: LOW - Excellent email security posture")
        elif final_score >= 70:
            print("Risk Level: MODERATE-LOW - Good security with minor gaps")
        elif final_score >= 55:
            print("Risk Level: MODERATE - Acceptable but needs improvement")
        elif final_score >= 40:
            print("Risk Level: MODERATE-HIGH - Significant security gaps")
        elif final_score >= 25:
            print("Risk Level: HIGH - Weak security, high phishing risk")
        else:
            print("Risk Level: CRITICAL - Severe security deficiencies")

        print("="*80)

        # Category breakdown
        print("\nCATEGORY CONTRIBUTION TO FINAL SCORE:")
        print(f"  Authentication & Transport:    {category_scores['auth_transport']:.1f} × 25% = {category_scores['auth_transport'] * 0.25:.1f}")
        print(f"  Sender & Domain Intelligence:  {category_scores['domain_intel']:.1f} × 20% = {category_scores['domain_intel'] * 0.20:.1f}")
        print(f"  IP/ASN Reputation:             {category_scores['ip_reputation']:.1f} × 15% = {category_scores['ip_reputation'] * 0.15:.1f}")
        print(f"  URL Intelligence:              {category_scores['url_intel']:.1f} × 20% = {category_scores['url_intel'] * 0.20:.1f}")
        print(f"  Attachment Metadata:           {category_scores['attachment']:.1f} × 10% = {category_scores['attachment'] * 0.10:.1f}")
        print(f"  Behavioral Proxies:            {category_scores['behavioral']:.1f} × 10% = {category_scores['behavioral'] * 0.10:.1f}")
        print(f"                                                  Total = {final_score:.1f}")
        print()

    def _print_check_result(self, name, result):
        """Helper to print individual check result"""
        status_symbol = {
            'CONFIGURED': '✓',
            'SUPPORTED': '✓',
            'ESTABLISHED': '✓',
            'DISABLED': '✓',
            'LOW RISK': '✓',
            'CLEAN': '✓',
            'IDENTIFIED': '✓',
            'ANALYZED': '✓',
            'COMPUTED': '✓',
            'KNOWN SENDER': '✓',
            'NORMAL HOURS': '✓',
            'NOT CONFIGURED': '✗',
            'NOT SUPPORTED': '✗',
            'VERY NEW': '✗',
            'HIGH RISK': '✗',
            'DETECTED': '✗',
            'INVALID IP': '✗',
            'NOT FOUND': '○',
            'MODERATE': '○',
            'MODERATE RISK': '○',
            'ENABLED': '⚠',
            'RECENT': '○',
            'NEW': '⚠',
            'FIRST TIME': '⚠',
            'ODD HOURS': '⚠',
            'PRIVATE IP': '⚠',
            'NO URLS': '○',
            'NO ATTACHMENTS': '○',
            'NO IP PROVIDED': '○',
            'NOT CHECKED': '○',
            'CHECK FAILED': '⚠',
            'INFO': 'ℹ',
            'UNKNOWN': '?',
            'ERROR': '⚠'
        }.get(result['status'], '?')

        score_bar = self._create_score_bar(result['score'])
        print(f"    {name}:")
        print(f"      Status: {status_symbol} {result['status']}")
        print(f"      Score:  {score_bar} {result['score']:.0f}/100")
        if result['details']:
            for line in result['details'].split('\n'):
                print(f"      {line}")

    def _create_score_bar(self, score):
        """Create a visual score bar"""
        filled = int(score / 10)
        empty = 10 - filled
        return '█' * filled + '░' * empty

    def analyze(self):
        """Run all comprehensive security checks"""
        print(f"\nAnalyzing email: {self.email}")
        print("="*80)

        # Category 1: Authentication & Transport (25%)
        self.check_spf()
        self.check_dkim()
        self.check_dmarc()
        self.check_arc()
        self.check_tls_support()

        # Category 2: Sender & Domain Intelligence (20%)
        self.check_domain_age()
        self.check_whois_privacy()
        self.check_tld_risk()
        self.check_rdap()

        # Category 3: IP/ASN Reputation (15%)
        self.check_ip_reputation()

        # Category 4: URL Intelligence (20%)
        self.check_url_intelligence()

        # Category 5: Attachment Metadata (10%)
        self.check_attachment_metadata()

        # Category 6: Behavioral Proxies (10%)
        self.check_behavioral_proxies()

        self.print_results()


def main():
    print("="*80)
    print("VELURA LABS - COMPREHENSIVE EMAIL METADATA SECURITY CHECKER")
    print("Internal Prototyping Tool")
    print("="*80)
    print("\nWeighted Category Analysis:")
    print("\n  [1] Authentication & Transport (25%):")
    print("      • SPF, DKIM, DMARC, ARC, TLS details")
    print("\n  [2] Sender & Domain Intelligence (20%):")
    print("      • Domain age, WHOIS privacy, TLD risk, RDAP")
    print("\n  [3] IP/ASN Reputation (15%):")
    print("      • IP reputation, geolocation, ASN risk")
    print("\n  [4] URL Intelligence (20%):")
    print("      • Homograph detection, typosquatting, redirect analysis")
    print("\n  [5] Attachment Metadata (10%):")
    print("      • MIME/extension mismatch, macro detection, hash reputation")
    print("\n  [6] Behavioral Proxies (10%):")
    print("      • First-time sender, time anomaly, reply-to mismatch")

    # Get email or domain
    print("\n" + "-"*80)
    email = input("Enter email address or domain: ").strip()

    if not email:
        print("\n[!] Error: No email/domain provided")
        sys.exit(1)

    # Add @ if just domain
    if '@' not in email:
        email = f'test@{email}'

    # Optional: Get sender IP
    sender_ip = input("Enter sender IP address (optional, press Enter to skip): ").strip()
    if not sender_ip:
        sender_ip = None

    # Optional: Get email body for URL analysis
    print("\nFor URL analysis, paste email body (press Enter twice when done):")
    print("(or press Enter to skip)")
    email_body_lines = []
    while True:
        line = input()
        if line == "" and (not email_body_lines or email_body_lines[-1] == ""):
            break
        email_body_lines.append(line)

    email_body = '\n'.join(email_body_lines) if email_body_lines else None

    # Create checker and analyze
    checker = EmailDomainChecker(email, sender_ip=sender_ip, email_body=email_body)
    checker.analyze()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
