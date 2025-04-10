from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from urllib.parse import urlparse
import ssl
import socket
import OpenSSL
from datetime import datetime
import logging
import re
from typing import Dict, Optional
from rest_framework.views import APIView
from rest_framework.response import Response

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 10
VALID_PORTS = {443}  # Only allow standard HTTPS port initially
MAX_HOSTNAME_LENGTH = 253  # Per RFC 1035

def validate_url(url: str) -> Optional[str]:
    """Validate and sanitize the input URL"""
    if not url:
        return None

    # Remove leading/trailing whitespace
    url = url.strip()

    # Basic format validation
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-.]+$', url):
        return None

    # Check length
    if len(url) > MAX_HOSTNAME_LENGTH:
        return None

    # Parse URL if protocol is included
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
    hostname = parsed.hostname

    if not hostname:
        return None

    return hostname.lower()

def get_cert_details(cert: Dict) -> Dict:
    """Extract certificate details safely"""
    try:
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])

        return {
            'issuer': issuer.get('organizationName', 'Unknown'),
            'subject': subject.get('commonName', 'Unknown'),
            'expires': not_after,
            'serial': cert.get('serialNumber', 'Unknown')
        }
    except Exception as e:
        logger.error(f"Error parsing cert details: {str(e)}")
        return {
            'issuer': 'Unknown',
            'subject': 'Unknown',
            'expires': datetime.now(),
            'serial': 'Unknown'
        }

class SSLCheckView(APIView):
    def post(self, request):
        if request.method == "POST":
            try:
                data = json.loads(request.body)
                url = data.get("url", "").strip()

                if not url:
                    return JsonResponse({"error": "URL is required"}, status=400)

                hostname = validate_url(url)
                if not hostname:
                    return JsonResponse({"error": "Invalid or malformed URL"}, status=400)

                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.check_hostname = True
                    context.load_default_certs()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2

                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(TIMEOUT_SECONDS)
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            try:
                                ssock.connect((hostname, 443))
                                cert = ssock.getpeercert()

                                if not cert:
                                    raise ValueError("No certificate received")

                                cert_details = get_cert_details(cert)
                                days_until_expiry = (cert_details['expires'] - datetime.now()).days

                                response_data = {
                                    'status': 'Valid SSL Certificate',
                                    'hostname': hostname,
                                    'issuer': cert_details['issuer'],
                                    'subject': cert_details['subject'],
                                    'serial_number': str(cert_details['serial']),
                                    'expires_on': cert_details['expires'].strftime('%Y-%m-%d'),
                                    'days_until_expiry': days_until_expiry,
                                    'valid': days_until_expiry > 0,
                                    'tls_version': ssock.version()
                                }

                                if days_until_expiry <= 30:
                                    response_data['warning'] = 'Certificate nearing expiration'

                                return JsonResponse(response_data)

                            except ssl.SSLCertVerificationError as e:
                                logger.warning(f"SSL check for {hostname}: {str(e)}")
                                response_data = {
                                    'status': 'Invalid SSL',
                                    'hostname': hostname,
                                    'issuer': 'Unknown',
                                    'subject': 'Unknown',
                                    'serial_number': 'Unknown',
                                    'expires_on': None,
                                    'days_until_expiry': 0,
                                    'valid': False,
                                    'tls_version': None
                                }
                                return JsonResponse(response_data)

                except socket.timeout:
                    logger.warning(f"Timeout connecting to {hostname}")
                    response_data = {
                        'status': 'Connection Timeout',
                        'hostname': hostname,
                        'issuer': 'Unknown',
                        'subject': 'Unknown',
                        'serial_number': 'Unknown',
                        'expires_on': None,
                        'days_until_expiry': 0,
                        'valid': False,
                        'tls_version': None
                    }
                    response_data['error'] = f'Connection timeout after {TIMEOUT_SECONDS} seconds'
                    return JsonResponse(response_data)

                except (ssl.SSLError, socket.gaierror) as e:
                    logger.warning(f"SSL connection error for {hostname}: {str(e)}")
                    response_data = {
                        'status': 'SSL Connection Failed',
                        'hostname': hostname,
                        'issuer': 'Unknown',
                        'subject': 'Unknown',
                        'serial_number': 'Unknown',
                        'expires_on': None,
                        'days_until_expiry': 0,
                        'valid': False,
                        'tls_version': None
                    }
                    response_data['error'] = str(e)
                    return JsonResponse(response_data)

                except Exception as e:
                    logger.error(f"Unexpected error checking SSL for {hostname}: {str(e)}")
                    response_data = {
                        'status': 'Internal Server Error',
                        'hostname': hostname,
                        'issuer': 'Unknown',
                        'subject': 'Unknown',
                        'serial_number': 'Unknown',
                        'expires_on': None,
                        'days_until_expiry': 0,
                        'valid': False,
                        'tls_version': None
                    }
                    response_data['error'] = 'Internal server error during SSL check'
                    return JsonResponse(response_data)

            except json.JSONDecodeError:
                response_data = {
                    'status': 'Invalid Request',
                    'hostname': None,
                    'issuer': 'Unknown',
                    'subject': 'Unknown',
                    'serial_number': 'Unknown',
                    'expires_on': None,
                    'days_until_expiry': 0,
                    'valid': False,
                    'tls_version': None,
                    'error': 'Invalid JSON format'
                }
                return JsonResponse(response_data)

        return JsonResponse({
            'status': 'Invalid Request Method',
            'hostname': None,
            'issuer': 'Unknown',
            'subject': 'Unknown',
            'serial_number': 'Unknown',
            'expires_on': None,
            'days_until_expiry': 0,
            'valid': False,
            'tls_version': None,
            'error': 'Invalid request method'
        })