#!/usr/bin/env python3
"""External Triton inference watchdog with persistent, deduplicated SMTP alerts."""
import argparse
from datetime import datetime, timezone
from email.message import EmailMessage
import fcntl
import http.client
import json
import math
from pathlib import Path
import re
import secrets
import smtplib
import ssl
import time
from urllib.parse import urlsplit

OUTPUTS = {'injection_logits': 1, 'sensitive_logits': 9, 'tool_class_logits': 14,
           'tool_action_logits': 6, 'tool_tags_logits': 3, 'routing_logits': 5,
           'threat_logits': 7}


def validate(response, model):
    if not isinstance(response, dict):
        raise ValueError('Invalid inference response')
    if response.get('model_name') != model or response.get('model_version') != '1':
        raise ValueError('Wrong inference model/version')
    outputs = response.get('outputs', [])
    if not isinstance(outputs, list) or len(outputs) != len(OUTPUTS):
        raise ValueError('Missing inference outputs')
    seen = set()
    for output in outputs:
        if not isinstance(output, dict):
            raise ValueError('Invalid inference output')
        name = output.get('name')
        if name not in OUTPUTS or name in seen:
            raise ValueError('Unexpected or duplicate output')
        seen.add(name)
        values = output.get('data', [])
        if (output.get('shape') != [1, OUTPUTS[name]] or
                output.get('datatype') != 'FP32' or len(values) != OUTPUTS[name] or
                any(type(v) not in (int, float) or not math.isfinite(v) for v in values)):
            raise ValueError('Invalid inference tensor')


def probe(config):
    url = urlsplit(config['triton_url'])
    if (url.scheme not in ('http', 'https') or not url.hostname or url.username or
            url.password or url.path not in ('', '/') or url.query or url.fragment):
        raise ValueError('Invalid Triton origin')
    model = config['model']
    if not re.fullmatch(r'[A-Za-z0-9_-]+', model):
        raise ValueError('Invalid model name')
    # Valid synthetic token IDs, varied to avoid a cached response hiding GPU failure.
    tokens = [0] + [secrets.randbelow(100) + 3 for _ in range(16)] + [2]
    ids = tokens + [1] * (256 - len(tokens))
    mask = [1] * len(tokens) + [0] * (256 - len(tokens))
    body = json.dumps({'inputs': [
        {'name': 'input_ids', 'shape': [1, 256], 'datatype': 'INT64', 'data': ids},
        {'name': 'attention_mask', 'shape': [1, 256], 'datatype': 'INT64', 'data': mask},
    ], 'outputs': [{'name': name} for name in OUTPUTS]})
    cls = http.client.HTTPSConnection if url.scheme == 'https' else http.client.HTTPConnection
    connection = cls(url.hostname, url.port, timeout=5)
    start = time.monotonic()
    try:
        connection.request('POST', f'/v2/models/{model}/versions/1/infer', body,
                           {'Content-Type': 'application/json'})
        response = connection.getresponse()
        data = response.read(65537)
        if response.status != 200:
            raise ValueError(f'Triton inference HTTP {response.status}')
        if len(data) > 65536:
            raise ValueError('Oversized inference response')
        validate(json.loads(data), model)
        return round((time.monotonic() - start) * 1000, 2)
    finally:
        connection.close()


def advance(previous, ok, detail, now, threshold=3):
    state = dict(previous)
    state.update(last_check=now, healthy=ok, detail=detail)
    if ok:
        state['failures'] = 0
        event = 'RECOVERED' if state.get('alert_sent', False) else None
    else:
        state['failures'] = state.get('failures', 0) + 1
        if state['failures'] == 1:
            state['failure_since'] = now
        event = 'DOWN' if state['failures'] >= threshold and not state.get('alert_sent', False) else None
    return state, event


def notify(config, event, state):
    mail = config['mail']
    message = EmailMessage()
    message['From'] = mail['from']
    message['To'] = mail['to']
    message['Subject'] = f"[Ark L3] {event}"
    message.set_content(
        f"Ark L3 inference: {event}\nTime (UTC): {state['last_check']}\n"
        f"First failure: {state.get('failure_since', 'unknown')}\n"
        f"Detail: {state['detail']}\nConsecutive failures: {state['failures']}\n"
        "Checked from the monitoring host using a real Triton inference, not the readiness endpoint.\n")
    context = ssl.create_default_context()
    mode = mail.get('tls', 'starttls')
    if mode == 'ssl':
        smtp = smtplib.SMTP_SSL(mail['host'], mail.get('port', 465), timeout=10, context=context)
    elif mode == 'starttls':
        smtp = smtplib.SMTP(mail['host'], mail.get('port', 587), timeout=10)
    else:
        raise ValueError('SMTP TLS is required')
    with smtp:
        if mode == 'starttls':
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
        if mail.get('username'):
            smtp.login(mail['username'], mail['password'])
        refused = smtp.send_message(message)
        if refused:
            raise RuntimeError('SMTP recipient rejected')


def run(config, state_path):
    previous = json.loads(state_path.read_text()) if state_path.exists() else {}
    try:
        latency = probe(config)
        ok, detail = True, f'Inference OK ({latency} ms)'
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as exc:
        ok = False
        # Avoid persisting credentials, request text, or arbitrary server bodies.
        detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
    now = datetime.now(timezone.utc).isoformat()
    state, event = advance(previous, ok, detail, now)
    state['mail_configured'] = bool(config.get('mail'))
    state.pop('notification_error', None)
    if event and state['mail_configured']:
        try:
            notify(config, event, state)
        except Exception as exc:
            state['notification_error'] = type(exc).__name__
        else:
            state['alert_sent'] = event == 'DOWN'
            state['last_notification'] = {'event': event, 'at': now}
    temporary = state_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(state_path)
    print(json.dumps(state), flush=True)
    return 0 if ok and 'notification_error' not in state else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    args.state.parent.mkdir(parents=True, exist_ok=True)
    with args.state.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return run(json.loads(args.config.read_text()), args.state)


if __name__ == '__main__':
    raise SystemExit(main())
