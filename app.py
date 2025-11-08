from flask import Flask, render_template, request, redirect, url_for, abort, jsonify, Response, send_from_directory
import sqlite3, json, re, os, time
from datetime import datetime
from email import message_from_string
from pathlib import Path

# ✅ NEW: ensure reports directory exists for saved reports
if not os.path.exists('reports'):
    os.makedirs('reports')

DB_PATH = Path('reports.db')
SAMPLES_PATH = Path('sample_emails.json')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 300 * 1024  # 300 KB

# Load samples if present
SAMPLES = json.loads(SAMPLES_PATH.read_text()) if SAMPLES_PATH.exists() else []

# scoring config
WEIGHT = {'spf':0.2,'dkim':0.2,'dmarc':0.2,'returnpath':0.15,'keywords':0.15,'attachments':0.1}
PHISH_KEYWORDS = ['urgent','verify','account','password','login','update','click here','confirm','click','verify account']
SUSPICIOUS_EXT = ['.exe','.js','.scr','.bat','.ps1','.com']

# initialize DB
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        subject TEXT,
        verdict TEXT,
        score REAL,
        summary TEXT,
        data TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

# ----------------------
# Email parsing & analysis
# ----------------------
def parse_headers(eml_text):
    headers = {}
    try:
        msg = message_from_string(eml_text)
        for k,v in msg.items():
            headers[k] = v
    except Exception:
        for line in eml_text.splitlines():
            if ':' in line:
                k, v = line.split(':',1)
                headers[k.strip()] = v.strip()
    return headers

def analyze_email(eml_text):
    headers = parse_headers(eml_text)
    low = eml_text.lower()
    analysis = {'checks': {}, 'reasons': [], 'highlights': [], 'explanations': {}}

    # SPF / DKIM / DMARC
    for key in ['spf','dkim','dmarc']:
        if f'{key}=pass' in low or f'{key}: pass' in low or f'{key} pass' in low:
            analysis['checks'][key] = 'pass'
            analysis['explanations'][key] = f'{key.upper()} passed successfully.'
        elif f'{key}=fail' in low or f'{key}: fail' in low or f'{key} fail' in low:
            analysis['checks'][key] = 'fail'
            analysis['reasons'].append(f'{key.upper()} failed')
            analysis['highlights'].append(f'{key}')
            analysis['explanations'][key] = f'{key.upper()} failed or missing.'
        else:
            analysis['checks'][key] = 'neutral'
            analysis['explanations'][key] = f'{key.upper()} not clearly present.'

    # Return-Path mismatch
    from_addr = headers.get('From','')
    rp = headers.get('Return-Path','') or headers.get('return-path','')
    from_domain = from_addr.split('@')[-1].strip().lower() if '@' in from_addr else ''
    rp_domain = rp.replace('<','').replace('>','').split('@')[-1].strip().lower() if '@' in rp else ''
    if from_domain and rp_domain and from_domain != rp_domain:
        analysis['checks']['returnpath'] = 'fail'
        analysis['reasons'].append(f'Return-Path domain ({rp_domain}) ≠ From domain ({from_domain})')
        analysis['highlights'].append('Return-Path/From mismatch')
        analysis['explanations']['returnpath'] = 'Mismatch often indicates spoofing.'
    else:
        analysis['checks']['returnpath'] = 'pass'
        analysis['explanations']['returnpath'] = 'Return-Path matches From domain (or not present).'

    # Subject keywords
    subject = headers.get('Subject','').lower()
    found_kw = [kw for kw in PHISH_KEYWORDS if kw in subject]
    if found_kw:
        analysis['checks']['keywords'] = 'fail'
        analysis['reasons'].append('Phishing keywords: ' + ', '.join(found_kw))
        analysis['highlights'].append('Subject keywords')
        analysis['explanations']['keywords'] = 'Phishing-like words found.'
    else:
        analysis['checks']['keywords'] = 'pass'
        analysis['explanations']['keywords'] = 'No phishing words in subject.'

    # Attachments
    attachment_matches = re.findall(r'filename="([^"]+)"', eml_text, re.I)
    suspicious_attach = [f for f in attachment_matches if any(f.lower().endswith(e) for e in SUSPICIOUS_EXT)]
    if suspicious_attach:
        analysis['checks']['attachments'] = 'fail'
        analysis['reasons'].append('Suspicious attachments: ' + ', '.join(suspicious_attach))
        analysis['highlights'].extend(suspicious_attach)
        analysis['explanations']['attachments'] = 'Executable attachments are risky.'
    else:
        analysis['checks']['attachments'] = 'pass'
        analysis['explanations']['attachments'] = 'No executable attachments found.'

    # Duplicate headers
    header_keys = re.findall(r'(?m)^\s*([A-Za-z0-9\-]+):', eml_text)
    if len(header_keys) != len(set(header_keys)):
        analysis['reasons'].append('Duplicate headers detected')
        analysis['highlights'].append('Duplicate headers')
        analysis['checks']['header_anomalies'] = 'duplicate'
        analysis['explanations']['header_anomalies'] = 'Duplicate header fields may indicate tampering.'
    else:
        analysis['checks']['header_anomalies'] = 'ok'

    return headers, analysis

def map_score(val): return {'pass':1, 'fail':0, 'neutral':0.5}.get(val, 0.5)
def compute_confidence(checks): return round(sum(map_score(v)*WEIGHT.get(k,0) for k,v in checks.items())*100,1)
def short_verdict(score): return 'Legitimate' if score>=80 else ('Possibly spoofed' if score>=50 else 'Suspicious')
def eli5_action(v): return {'Legitimate':'Looks OK — verify links.', 'Possibly spoofed':'Be careful — verify sender.', 'Suspicious':'High risk — do NOT click anything.'}[v]

# ----------------------
# Routes
# ----------------------
@app.route('/')
def index(): return render_template('index.html', samples=SAMPLES)

@app.route('/analyze', methods=['POST'])
def analyze():
    payload = None
    if 'eml' in request.form and request.form['eml'].strip():
        payload = request.form['eml']
    elif 'file' in request.files:
        f = request.files['file']
        try: payload = f.read().decode('utf-8', errors='ignore')
        except: payload = f.read().decode('latin-1', errors='ignore')
    if not payload: return redirect(url_for('index'))

    headers, analysis = analyze_email(payload)
    score = compute_confidence(analysis['checks'])
    verdict = short_verdict(score)
    action = eli5_action(verdict)
    summary = '; '.join(analysis['reasons'][:3]) if analysis['reasons'] else ''
    ts = datetime.utcnow().isoformat() + 'Z'
    subj = headers.get('Subject','')

    data_blob = json.dumps({
        'headers': headers, 'analysis': analysis, 'score': score, 'verdict': verdict,
        'action': action, 'raw': payload, 'timestamp': ts
    })

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO reports (timestamp, subject, verdict, score, summary, data) VALUES (?,?,?,?,?,?)',
              (ts, subj, verdict, score, summary, data_blob))
    rid = c.lastrowid
    conn.commit()
    conn.close()

    # ✅ NEW: save HTML report file
    report_html = render_template('report.html', id=rid, headers=headers, analysis=analysis, score=score,
                                  verdict=verdict, action=action, raw=payload, timestamp=ts)
    filename = f'report_{rid}.html'
    path = os.path.join('reports', filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(report_html)
        f.flush()
        os.fsync(f.fileno())

    result = {
        "status": "Safe" if verdict == "Legitimate" else verdict,
        "confidence": score,
        "action": action,
        "reasons": analysis['reasons'] or ["No major issues detected."],
        "summary": summary or "No significant issues found."
    }

    return render_template('result.html', result=result, raw=payload, analysis=analysis,
                           report_filename=filename)  # ✅ Pass filename to template

# ✅ NEW: reliable download route
@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_from_directory('reports', filename, as_attachment=True)
    except FileNotFoundError:
        return "File not found. Please re-run the analysis.", 404

@app.route('/reports')
def reports_list():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, timestamp, subject, verdict, score, summary FROM reports ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return render_template('history.html', rows=rows)

@app.route('/dashboard')
def dashboard(): return render_template('dashboard.html')

@app.route('/dashboard_data')
def dashboard_data():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT data FROM reports ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()

    total = len(rows)
    verdict_counts = {'Legitimate':0, 'Possibly spoofed':0, 'Suspicious':0}
    spf_pass = dkim_pass = dmarc_pass = 0
    keywords_counter = {}
    recent = []

    for (raw_json,) in rows:
        try: payload = json.loads(raw_json)
        except: continue
        checks = payload.get('analysis', {}).get('checks', {})
        if checks.get('spf') == 'pass': spf_pass += 1
        if checks.get('dkim') == 'pass': dkim_pass += 1
        if checks.get('dmarc') == 'pass': dmarc_pass += 1
        v = payload.get('verdict','')
        if v in verdict_counts: verdict_counts[v]+=1
        for kw in payload.get('analysis', {}).get('highlights', []):
            keywords_counter[kw]=keywords_counter.get(kw,0)+1
        if len(recent)<10:
            recent.append({
                'id': payload.get('id',''),
                'subject': payload.get('headers', {}).get('Subject','-'),
                'verdict': v,
                'score': payload.get('score',0),
                'timestamp': payload.get('timestamp','')
            })

    spf_rate = round(spf_pass/total*100,1) if total else 0
    dkim_rate = round(dkim_pass/total*100,1) if total else 0
    dmarc_rate = round(dmarc_pass/total*100,1) if total else 0
    top_keywords = [k for k,_ in sorted(keywords_counter.items(), key=lambda x:x[1], reverse=True)[:8]]

    data = {
        "total_emails": total,
        "spf_success": spf_rate,
        "dkim_success": dkim_rate,
        "dmarc_success": dmarc_rate,
        "verdict_counts": verdict_counts,
        "top_keywords": top_keywords,
        "recent": recent
    }
    return jsonify(data)
@app.route('/report/<int:rid>')
def view_report(rid):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT data FROM reports WHERE id=?', (rid,))
    row = c.fetchone()
    conn.close()

    if not row:
        abort(404)

    payload = json.loads(row[0])
    headers = payload.get('headers', {})
    analysis = payload.get('analysis', {})
    score = payload.get('score', 0)
    verdict = payload.get('verdict', '')
    action = payload.get('action', '')
    raw = payload.get('raw', '')
    ts = payload.get('timestamp', '')

    # Render the saved report view
    return render_template('report.html', id=rid, headers=headers, analysis=analysis,
                           score=score, verdict=verdict, action=action, raw=raw, timestamp=ts)

if __name__ == '__main__':
    app.run(debug=True)