"""One-shot, read-only container status report from an explicit HTTPS origin."""

import argparse
from datetime import datetime, timedelta
import http.client
import json
import re
import ssl
import sys

from .observer import CONTAINER_ID_RE, PROJECT_RE
from .service import MAX_RESPONSE_BYTES, _token_from_file

TIMEOUT = 5.0


def fetch(url, ca_cert, token):
    # An origin only: no credentials, route, query, fragment or normalization.
    match = re.fullmatch(r'https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::([0-9]{1,5}))?/?', url)
    if not match:
        raise ValueError('invalid HTTPS origin')
    host, port = match.groups()
    port = int(port) if port else 443
    if not 1 <= port <= 65535:
        raise ValueError('invalid port')
    context = ssl.create_default_context(cafile=ca_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(
        host.strip('[]'), port, timeout=TIMEOUT, context=context)
    try:
        connection.request('GET', '/v1/containers', headers={
            'Authorization': 'Bearer ' + token, 'Connection': 'close',
            'Accept': 'application/json',
        })
        response = connection.getresponse()
        # http.client never follows redirects. Do not read error bodies.
        if response.status != 200:
            raise ValueError('observation request failed')
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError('response limit')
        # Bounded reads do not raise IncompleteRead on premature EOF.
        if response.length not in (None, 0):
            raise ValueError('incomplete response body')
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    finally:
        connection.close()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('invalid JSON constant')


def validate(value):
    if not isinstance(value, dict) or value.get('partial') is not False:
        raise ValueError('incomplete observation')
    if ('warnings' in value and value['warnings'] != []) or 'error' in value:
        raise ValueError('observation warnings')
    if not isinstance(value.get('host'), str) or not PROJECT_RE.fullmatch(value['host']):
        raise ValueError('invalid host')
    if value.get('source') not in ('docker-api', 'synthetic-fixture'):
        raise ValueError('invalid source')
    timestamp = value.get('observed_at')
    if not isinstance(timestamp, str):
        raise ValueError('missing timestamp')
    observed = datetime.fromisoformat(timestamp)
    if observed.utcoffset() != timedelta(0):
        raise ValueError('timestamp must be UTC')
    containers = value.get('containers')
    if not isinstance(containers, list) or len(containers) > 1000:
        raise ValueError('invalid inventory')
    ids = set()
    for row in containers:
        if not isinstance(row, dict) or not {'id', 'name', 'project', 'status', 'health'} <= row.keys():
            raise ValueError('missing container fields')
        identifier = row['id']
        if not isinstance(identifier, str) or not CONTAINER_ID_RE.fullmatch(identifier) or identifier in ids:
            raise ValueError('invalid container ID')
        ids.add(identifier)
        for field in ('name', 'status', 'health'):
            if row[field] is not None and not isinstance(row[field], str):
                raise ValueError('invalid container field')
        if row['project'] is not None and (
                not isinstance(row['project'], str) or not PROJECT_RE.fullmatch(row['project'])):
            raise ValueError('invalid project')
    return observed


def safe(value, token):
    """Bound terminal fields and remove control, bidi and non-ASCII characters."""
    value = value.replace(token, '[REDACTED]')
    return ''.join(c if ' ' <= c <= '~' else '?' for c in value[:80]) + ('...' if len(value) > 80 else '')


def report(value, token):
    observed = validate(value)
    rows = value['containers']
    lines = [f"Host: {safe(value['host'], token)} | Observed: {observed.isoformat()} (UTC)"]
    flagged = no_check = unhealthy = not_running = unknown = 0
    previous = object()
    for row in sorted(rows, key=lambda r: (r['project'] is None, r['project'] or '', r['name'] or '', r['id'])):
        if row['project'] != previous:
            lines.append('\nProject: ' + (safe(row['project'], token) if row['project'] is not None else '[unknown/unlabelled]'))
            previous = row['project']
        state = row['status']
        known = state in ('running', 'exited', 'dead', 'paused', 'restarting', 'created', 'removing')
        health = row['health']
        health_known = health in ('healthy', 'unhealthy', 'starting')
        missing = not known or (health is not None and not health_known) or not row['name'] or row['project'] is None
        stopped = known and state != 'running'
        bad = health == 'unhealthy'
        flagged += bool(missing or stopped or bad or health == 'starting')
        no_check += health is None
        unhealthy += bad
        not_running += stopped
        unknown += bool(missing)
        runtime = state if known else 'unknown/unavailable'
        health_text = ('no health check reported' if health is None else
                       health if health_known else 'unknown/unavailable')
        lines.append(f"  {safe(row['name'] or '[unknown name]', token)} [{safe(row['id'], token)[:12]}]  runtime={runtime}  health={health_text}")
    if not rows:
        lines.append('Inventory is empty (0 containers).')
    lines.append(f'\nTotal: {len(rows)} containers; {flagged} flagged; {not_running} not running; '
                 f'{unhealthy} unhealthy; {unknown} unknown; {no_check} with no health check reported.')
    # Retain final redaction as defense in depth after per-field redaction.
    return '\n'.join(lines).replace(token, '[REDACTED]'), int(flagged > 0)


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse otherwise echoes arbitrary arguments, potentially credentials.
        self.exit(2, 'Invalid arguments; use --help for usage.\n')


def main(argv=None):
    parser = QuietParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--url', required=True, help='HTTPS origin only')
    parser.add_argument('--ca-cert', help='CA PEM file (default: system trust store)')
    parser.add_argument('--token-file', required=True, help='Private regular credential file')
    args = parser.parse_args(argv)
    try:
        token = _token_from_file(args.token_file)
        if any(not '!' <= c <= '~' for c in token):
            raise ValueError('invalid credential')
        output, code = report(fetch(args.url, args.ca_cert, token), token)
    except (OSError, ValueError, http.client.HTTPException, RecursionError):
        print('Observation unavailable: check HTTPS/TLS, credential file, connectivity, and complete API data.', file=sys.stderr)
        return 2
    print(output)
    return code


if __name__ == '__main__':
    sys.exit(main())
