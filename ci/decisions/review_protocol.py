#!/usr/bin/env python3
"""Exact-head authenticated Comment-review commands shared by native consumers."""
import json
import sys


def effective_review(review, head):
    if review.get('state') == 'COMMENTED':
        body = review.get('body')
        if body is None:
            body = ''
        if not isinstance(body, str):
            raise ValueError('Invalid authenticated review body')
        if review.get('commit_id') != head:
            return None
        command = body.strip()
        if command == '/decider approve ' + head:
            return {**review, 'state': 'APPROVED', 'approvalMethod': 'comment-review'}
        if command == '/decider withdraw ' + head:
            return {**review, 'state': 'DISMISSED', 'approvalMethod': 'comment-review'}
        return None
    if review.get('state') in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'):
        return review
    return None


def exact_head_reviewers(pages, head):
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise ValueError('Invalid paginated review collection')
    latest = {}
    for page in pages:
        for value in page:
            if (not isinstance(value, dict) or type(value.get('id')) is not int
                    or value['id'] < 1 or not isinstance(value.get('user'), dict)):
                raise ValueError('Invalid authenticated PR review record')
            review = effective_review(value, head)
            if review is None or review.get('commit_id') != head:
                continue
            user = review['user']
            if user.get('type') == 'Bot':
                continue
            login = user.get('login')
            if not isinstance(login, str) or not login or not all(c.isascii() and (c.isalnum() or c == '-') for c in login):
                raise ValueError('Invalid reviewer login')
            key = login.lower()
            if key not in latest or latest[key]['id'] < review['id']:
                latest[key] = review
    return [review['user']['login'] for review in latest.values() if review['state'] == 'APPROVED']


if __name__ == '__main__':
    try:
        for reviewer in exact_head_reviewers(json.load(sys.stdin), sys.argv[1]):
            print(reviewer)
    except (ValueError, TypeError, IndexError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
