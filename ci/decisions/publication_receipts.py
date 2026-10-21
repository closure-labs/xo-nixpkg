# SPDX-License-Identifier: Apache-2.0
"""Backward-compatible readers for verified destination receipt version1."""
import datetime as dt
import json
import re

DESTINATIONS = {'cache', 'handoff', 'github', 'github-release', 'xo-tag', 'project-tag', 'flakehub'}


def validate(receipt, product_hash, destination):
    keys = {'schema', 'productHash', 'destination', 'status', 'expected', 'observed', 'verifiedAt', 'verifier'}
    if (not isinstance(receipt, dict) or set(receipt) != keys or type(receipt['schema']) is not int
            or receipt['schema'] != 1 or receipt['productHash'] != product_hash
            or destination not in DESTINATIONS or receipt['destination'] != destination
            or receipt['status'] != 'verified' or not isinstance(receipt['expected'], dict)
            or not receipt['expected'] or json.dumps(receipt['observed'], sort_keys=True, allow_nan=False) != json.dumps(receipt['expected'], sort_keys=True, allow_nan=False)
            or not isinstance(receipt['verifier'], str) or not re.fullmatch(r'[a-f0-9]{64}', receipt['verifier'])
            or len(json.dumps(receipt, allow_nan=False).encode()) > 128 * 1024):
        raise ValueError('Invalid verified publication receipt')
    if not isinstance(receipt['verifiedAt'], str):
        raise ValueError('Receipt verification time required')
    timestamp = dt.datetime.fromisoformat(receipt['verifiedAt'].replace('Z', '+00:00'))
    if timestamp.tzinfo is None:
        raise ValueError('Receipt verification time requires timezone')
    return receipt


def read(document, product_hash):
    """Legacy completion is preserved but grants no proof of current remote state."""
    if not isinstance(document, dict):
        raise ValueError('Invalid publication journal document')
    schema = document.get('schema')
    if type(schema) is not int or schema not in (1, 2) or document.get('productHash') != product_hash:
        raise ValueError('Invalid publication journal identity or version')
    if schema == 1:
        if 'receipts' in document:
            raise ValueError('Legacy journal cannot contain new receipt fields')
        return {}
    receipts = document.get('receipts')
    if not isinstance(receipts, dict):
        raise ValueError('Version2 publication journal requires receipts')
    for destination, receipt in receipts.items():
        validate(receipt, product_hash, destination)
    return receipts
