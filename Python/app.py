from flask import Flask, render_template, request, redirect, url_for, abort, jsonify, send_from_directory
import sqlite3, json, re, os
from datetime import datetime
from email import message_from_string
from pathlib import Path

# ----------------------
# Setup
# ----------------------
if not os.path.exists('reports'):
    os.makedirs('reports')

DB_PATH = Path('reports.db')
SAMPLES_PATH = Path('sample_emails.json')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 300 * 1024  # 300 KB

SAMPLES = json.loads(SAMPLES_PATH.read_text()) if SAMPLES_PATH.exists() else []

PHISH_KEYWORDS = ['urgent','verify','account','password','login','update','click here','confirm','click','verify account']
SUSPICIOUS_EXT = ['.exe','.js','.scr','.bat','.ps1']

# ----------------------
# Database
# ----------------------
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
# Parsing & analysis
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

def map_score(val): return {'pass':1, 'fail':0, 'neutral':0.5, 'ok':1, 'duplicate':0.3}.get(val,0.5)

# Improved analysis logic
WEIGHT_SAFE = {
    'spf':0.3,
    'dkim':0.3,
    'dmarc':0.3,
    'returnpath':0.05,
    'keywords':0.025,
    'attachments':0.025,
    'header_anomalies':0.05
}

def compute_confidence_safe(checks):
    raw_score = sum(map_score(v)*WEIGHT_SAFE.get(k,0) for k,v in checks.items())
    return round(min(raw_score*100, 100), 1)


def short_verdict(score):
    if score>=80: return 'Legitimate'
    elif score>=50: return 'Possibly spoofed'
    else: return 'Suspicious'

def eli5_action(v):
    return {'Legitimate':'No actions needed',
            'Possibly spoofed':'Be careful — verify sender.',
            'Suspicious':'High risk — do NOT click anything.'}[v]

def analyze_email_safe(eml_text):
    headers = parse_headers(eml_text)
    low = eml_text.lower()
    analysis = {'checks': {}, 'reasons': [], 'highlights': [], 'explanations': {}}

    # SPF/DKIM/DMARC
    for key in ['spf','dkim','dmarc']:
        if f'{key}=pass' in low or f'{key}: pass' in low or f'{key} pass' in low:
            analysis['checks'][key]='pass'
            analysis['explanations'][key]=f'{key.upper()} passed successfully.'
        elif f'{key}=fail' in low or f'{key}: fail' in low or f'{key} fail' in low:
            analysis['checks'][key]='fail'
            analysis['reasons'].append(f'{key.upper()} failed')
            analysis['highlights'].append(key)
            analysis['explanations'][key]=f'{key.upper()} failed or missing.'
        else:
            analysis['checks'][key]='neutral'
            analysis['explanations'][key]=f'{key.upper()} not clearly present.'

    # Return-Path
    def clean_domain(addr):
        if not addr: return ''
        addr = addr.replace('<','').replace('>','').strip()
        match = re.search(r'@([A-Za-z0-9\.-]+)', addr)
        return match.group(1).lower().rstrip('.') if match else ''
    from_domain = clean_domain(headers.get('From',''))
    rp_domain = clean_domain(headers.get('Return-Path','') or headers.get('return-path',''))

    if from_domain and rp_domain:
        from_parts = from_domain.split('.')
        rp_parts = rp_domain.split('.')
        if rp_parts[-2:] == from_parts[-2:]:
            analysis['checks']['returnpath']='pass'
            analysis['explanations']['returnpath']='Return-Path domain matches From domain.'
        else:
            if all(analysis['checks'].get(k)=='pass' for k in ['spf','dkim','dmarc']):
                analysis['checks']['returnpath']='neutral'
                analysis['explanations']['returnpath']='Return-Path differs, but SPF/DKIM/DMARC pass.'
            else:
                analysis['checks']['returnpath']='fail'
                analysis['reasons'].append(f'Return-Path domain ({rp_domain}) ≠ From domain ({from_domain})')
                analysis['highlights'].append('Return-Path/From mismatch')
                analysis['explanations']['returnpath']='Return-Path and From domains differ — may indicate spoofing.'
    else:
        analysis['checks']['returnpath']='neutral'
        analysis['explanations']['returnpath']='Return-Path info missing.'

    # Subject keywords
    subject = headers.get('Subject','').lower()
    found_kw = [kw for kw in PHISH_KEYWORDS if kw in subject]
    if found_kw:
        analysis['checks']['keywords']='neutral'
        analysis['reasons'].append('Phishing-like keywords detected: '+', '.join(found_kw))
        analysis['highlights'].append('Subject keywords')
        analysis['explanations']['keywords']='Subject contains suspicious keywords but not decisive.'
    else:
        analysis['checks']['keywords']='pass'
        analysis['explanations']['keywords']='No suspicious words detected.'

    # Attachments
    attachment_matches = re.findall(r'filename="([^"]+)"', eml_text, re.I)
    suspicious_attach = [f for f in attachment_matches if any(f.lower().endswith(e) for e in SUSPICIOUS_EXT)]
    if suspicious_attach:
        analysis['checks']['attachments']='neutral'
        analysis['reasons'].append('Suspicious attachments: '+', '.join(suspicious_attach))
        analysis['highlights'].extend(suspicious_attach)
        analysis['explanations']['attachments']='Executable attachments detected — exercise caution.'
    else:
        analysis['checks']['attachments']='pass'
        analysis['explanations']['attachments']='No executable attachments found.'

    # Duplicate headers
    header_keys = re.findall(r'(?m)^\s*([A-Za-z0-9\-]+):', eml_text)
    duplicates = [k for k in set(header_keys) if header_keys.count(k)>1 and k.lower() in ['from','to','subject','return-path']]
    if duplicates:
        analysis['checks']['header_anomalies']='neutral'
        analysis['reasons'].append(f'Duplicate critical headers: {", ".join(duplicates)}')
        analysis['highlights'].append('Duplicate headers')
        analysis['explanations']['header_anomalies']='Repeated headers detected — may indicate tampering.'
    else:
        analysis['checks']['header_anomalies']='ok'
        analysis['explanations']['header_anomalies']='No duplicate headers found.'

    return headers, analysis

# ----------------------
# Routes
# ----------------------
@app.route('/')
def index(): return render_template('index.html', samples=SAMPLES)

@app.route('/analyze', methods=['POST'])
def analyze():
    payload=None
    if 'eml' in request.form and request.form['eml'].strip():
        payload = request.form['eml']
    elif 'file' in request.files:
        f = request.files['file']
        try: payload = f.read().decode('utf-8', errors='ignore')
        except: payload = f.read().decode('latin-1', errors='ignore')
    if not payload: return redirect(url_for('index'))

    headers, analysis = analyze_email_safe(payload)
    score = compute_confidence_safe(analysis['checks'])
    verdict = short_verdict(score)
    action = eli5_action(verdict)
    summary = '; '.join(analysis['reasons'][:3]) if analysis['reasons'] else ''
    ts = datetime.utcnow().isoformat()+'Z'
    subj = headers.get('Subject','')

    data_blob = json.dumps({
        'headers': headers, 'analysis': analysis, 'score': score,
        'verdict': verdict, 'action': action, 'raw': payload, 'timestamp': ts
    })

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO reports (timestamp, subject, verdict, score, summary, data) VALUES (?,?,?,?,?,?)',
              (ts, subj, verdict, score, summary, data_blob))
    rid = c.lastrowid
    conn.commit()
    conn.close()

    report_html = render_template('report.html', id=rid, headers=headers, analysis=analysis,
                                  score=score, verdict=verdict, action=action, raw=payload, timestamp=ts)
    filename = f'report_{rid}.html'
    with open(os.path.join('reports', filename),'w',encoding='utf-8') as f:
        f.write(report_html)

    result = {
        "status": "Safe" if verdict=="Legitimate" else verdict,
        "confidence": score,
        "action": action,
        "reasons": analysis['reasons'] or ["No major issues detected."],
        "summary": summary or "No significant issues found."
    }

    return render_template('result.html', result=result, raw=payload, analysis=analysis,
                           report_filename=filename)

@app.route('/download/<filename>')
def download_file(filename):
    try: return send_from_directory('reports', filename, as_attachment=True)
    except FileNotFoundError: return "File not found. Please re-run the analysis.", 404

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

    total=len(rows)
    verdict_counts={'Legitimate':0,'Possibly spoofed':0,'Suspicious':0}
    spf_pass=dkim_pass=dmarc_pass=0
    keywords_counter={}
    recent=[]

    for (raw_json,) in rows:
        try: payload=json.loads(raw_json)
        except: continue
        checks=payload.get('analysis',{}).get('checks',{})
        if checks.get('spf')=='pass': spf_pass+=1
        if checks.get('dkim')=='pass': dkim_pass+=1
        if checks.get('dmarc')=='pass': dmarc_pass+=1
        v=payload.get('verdict','')
        if v in verdict_counts: verdict_counts[v]+=1
        for kw in payload.get('analysis',{}).get('highlights',[]):
            keywords_counter[kw]=keywords_counter.get(kw,0)+1
        if len(recent)<10:
            recent.append({
                'id': payload.get('id',''),
                'subject': payload.get('headers',{}).get('Subject','-'),
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
    conn=sqlite3.connect(DB_PATH)
    c=conn.cursor()
    c.execute('SELECT data FROM reports WHERE id=?',(rid,))
    row=c.fetchone()
    conn.close()
    if not row: abort(404)

    payload=json.loads(row[0])
    headers=payload.get('headers',{})
    analysis=payload.get('analysis',{})
    score=payload.get('score',0)
    verdict=payload.get('verdict','')
    action=payload.get('action','')
    raw=payload.get('raw','')
    ts=payload.get('timestamp','')

    return render_template('report.html', id=rid, headers=headers, analysis=analysis,
                           score=score, verdict=verdict, action=action, raw=raw, timestamp=ts)

if __name__=='__main__':
    app.run(debug=True)
