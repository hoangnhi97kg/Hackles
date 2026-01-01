"""HMAC authentication for BloodHound CE API.

BloodHound uses a 3-stage HMAC-SHA256 chain for request signing:
1. OperationKey: HMAC(token_key, method + uri)
2. DateKey: HMAC(op_key, datetime[:13])  # Hourly precision prevents replay
3. Signature: HMAC(date_key, body)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime
from typing import Dict, Optional, Tuple


def generate_signature(
    method: str,
    uri: str,
    token_key: str,
    body: Optional[bytes] = None,
    request_datetime: Optional[str] = None
) -> Tuple[str, str]:
    """Generate HMAC signature for BloodHound CE API request.

    Args:
        method: HTTP method (GET, POST, etc.)
        uri: Request URI (e.g., /api/v2/self)
        token_key: API token secret key
        body: Optional request body bytes
        request_datetime: Optional ISO8601 datetime (defaults to now)

    Returns:
        Tuple of (base64_signature, request_datetime)
    """
    # Get current datetime in ISO8601 format
    if request_datetime is None:
        request_datetime = datetime.now().astimezone().isoformat('T')

    # Stage 1: Operation key - combines method and URI
    digester = hmac.new(token_key.encode(), None, hashlib.sha256)
    digester.update(f'{method}{uri}'.encode())

    # Stage 2: Date key - hourly precision to prevent replay attacks
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    digester.update(request_datetime[:13].encode())  # "2024-01-15T14"

    # Stage 3: Body signature
    digester = hmac.new(digester.digest(), None, hashlib.sha256)
    if body is not None:
        digester.update(body)

    signature = base64.b64encode(digester.digest()).decode()
    return signature, request_datetime


def build_auth_headers(
    method: str,
    uri: str,
    token_id: str,
    token_key: str,
    body: Optional[bytes] = None
) -> Dict[str, str]:
    """Build authentication headers for BloodHound CE API request.

    Args:
        method: HTTP method (GET, POST, etc.)
        uri: Request URI (e.g., /api/v2/self)
        token_id: API token ID
        token_key: API token secret key
        body: Optional request body bytes

    Returns:
        Dict with Authorization, RequestDate, and Signature headers
    """
    signature, request_datetime = generate_signature(method, uri, token_key, body)

    return {
        'Authorization': f'bhesignature {token_id}',
        'RequestDate': request_datetime,
        'Signature': signature,
    }
