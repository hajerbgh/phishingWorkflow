from fastapi import FastAPI
from pydantic import BaseModel
import re
import hashlib
import os
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import requests
from datetime import datetime
from urllib.parse import urlparse
import base64
import unicodedata

app = FastAPI(title="Phishing Email Analyzer API")

# Récupération de la clé API VirusTotal depuis l'environnement
VT_API_KEY = os.getenv("VT_API_KEY")

# Simple dictionnaire de cache pour VirusTotal
vt_cache = {}
domain_cache = {}

# --- CHARGEMENT DE L'ALLOWLIST ---
ALLOWLIST = set()
ALLOWLIST_FILE = "allowlist.txt"

if os.path.exists(ALLOWLIST_FILE):
    with open(ALLOWLIST_FILE, "r") as f:
        ALLOWLIST = set(line.strip().lower() for line in f if line.strip())
else:
    with open(ALLOWLIST_FILE, "w") as f:
        f.write("gmail.com\ngoogle.com\nmicrosoft.com\nmicrosoftonline.com\n")
    ALLOWLIST = {"gmail.com", "google.com", "microsoft.com", "microsoftonline.com"}

class EmailPayload(BaseModel):
    rawEmail: str

class BlockRequest(BaseModel):
    domains: list[str]

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return list(set(re.findall(url_pattern, text)))

# --- ENRICHISSEMENT RDAP ---
def get_domain_age(domain: str):
    if not domain or domain in ALLOWLIST:
        return None
    if domain in domain_cache:
        return domain_cache[domain]

    url = f"https://rdap.org/domain/{domain}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") == "registration":
                    reg_date_str = event.get("eventDate")
                    reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                    age_days = (datetime.now(reg_date.tzinfo) - reg_date).days
                    domain_cache[domain] = age_days
                    return age_days
    except Exception as e:
        print(f"Erreur RDAP pour {domain}: {e}")
    return None

# --- VIRUSTOTAL URL ---
def check_virustotal_url(target_url: str):
    if not VT_API_KEY:
        return {"vt_status": "no_key", "malicious": 0}

    if target_url in vt_cache:
        return vt_cache[target_url]

    url_bytes = target_url.encode("utf-8")
    url_id = base64.urlsafe_b64encode(url_bytes).decode("utf-8").strip("=")
    
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(vt_url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "vt_status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            }
            vt_cache[target_url] = result
            return result
        elif response.status_code == 404:
            result = {"vt_status": "unknown", "malicious": 0}
            vt_cache[target_url] = result
            return result
        elif response.status_code == 429:
            return {"vt_status": "rate_limited", "malicious": 0}
    except Exception as e:
        print(f"Erreur VirusTotal URL: {e}")

    return {"vt_status": "error", "malicious": 0}

# --- VIRUSTOTAL FICHIER (HASH SHA256) ---
def check_virustotal_file(sha256: str):
    if not VT_API_KEY:
        return {"vt_status": "no_key", "malicious": 0}
    if sha256 in vt_cache:
        return vt_cache[sha256]
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                         headers={"x-apikey": VT_API_KEY}, timeout=5)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {"vt_status": "success", "malicious": stats.get("malicious", 0)}
        elif r.status_code == 404:
            result = {"vt_status": "unknown", "malicious": 0}
        else:
            return {"vt_status": "error", "malicious": 0}
        vt_cache[sha256] = result
        return result
    except Exception as e:
        print(f"Erreur VT fichier: {e}")
        return {"vt_status": "error", "malicious": 0}

# --- ANALYSE PAR RÈGLES ---
PRESSURE_WORDS = [
    "urgen", "immediat", "suspen", "bloque", "verif", "requis", "action",
    "expir", "alerte", "dernier avertissement", "security alert"
]

def check_pressure_words(subject: str, body: str):
    text = unicodedata.normalize("NFKD", (subject + " " + body).lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    count = sum(1 for word in PRESSURE_WORDS if word in text)
    return count >= 2, count

TARGET_BRANDS = ["paypal", "microsoft", "google", "apple", "netflix", "societegenerale", "creditagricole", "bnpparibas"]

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_typosquatting(domain: str):
    if not domain:
        return False, None
    labels = domain.lower().split('.')
    if len(labels) < 2:
        return False, None

    registered_full = ".".join(labels[-2:])
    if labels[-2] in TARGET_BRANDS or registered_full in ALLOWLIST:
        return False, None

    for label in labels[:-1]:
        for segment in label.split('-'):
            for brand in TARGET_BRANDS:
                if segment == brand:
                    return True, brand
                if len(brand) >= 6 and segment.startswith(brand):
                    return True, brand
                max_dist = 2 if len(brand) >= 6 else 1
                if 0 < levenshtein_distance(segment, brand) <= max_dist:
                    return True, brand
    return False, None

RISKY_EXTENSIONS = ['.exe', '.js', '.vbs', '.scr', '.iso', '.html', '.docm', '.xlsm', '.zip']

def check_risky_attachment(filename: str):
    filename_lower = filename.lower()
    parts = filename_lower.split('.')
    is_double_ext = len(parts) > 2 and parts[-1] in ['exe', 'scr', 'js', 'vbs']
    ext = os.path.splitext(filename_lower)[1]
    return ext in RISKY_EXTENSIONS or is_double_ext, ext, is_double_ext

@app.post("/analyze")
async def analyze_email(payload: EmailPayload):
    content = payload.rawEmail.encode('utf-8')
    msg = BytesParser(policy=policy.default).parsebytes(content)

    subject = msg.get('Subject', 'N/A')
    raw_from = msg.get('From', 'N/A')
    raw_reply_to = msg.get('Reply-To', 'N/A')
    return_path = msg.get('Return-Path', 'N/A')
    auth_results = msg.get('Authentication-Results', 'N/A')

    name, email_addr = parseaddr(raw_from)

    body_text = ""
    body_html = ""
    for part in msg.walk():
        if 'attachment' in str(part.get('Content-Disposition', '')):
            continue
        try:
            payload_data = part.get_payload(decode=True)
            if payload_data:
                decoded = payload_data.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                if part.get_content_type() == 'text/plain':
                    body_text += decoded
                elif part.get_content_type() == 'text/html':
                    body_html += decoded
        except:
            pass

    full_content = body_text + " " + body_html
    found_urls = extract_urls(full_content)

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename() or "inconnu"
        file_data = part.get_payload(decode=True)
        sha256 = hashlib.sha256(file_data).hexdigest() if file_data else "N/A"
        
        vt_file = check_virustotal_file(sha256) if file_data else {"vt_status": "none", "malicious": 0}
        attachments.append({
            "filename": filename,
            "size": len(file_data) if file_data else 0,
            "sha256": sha256,
            "vt_malicious": vt_file["malicious"],
            "vt_status": vt_file["vt_status"]
        })

    # --- ENRICHISSEMENT ---
    enrichment_results = {"domains": {}}
    filtered_urls = []
    for url in found_urls:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if domain and domain.lower() not in ALLOWLIST:
            filtered_urls.append(url)

    urls_to_check = filtered_urls[:3]
    for url in urls_to_check:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if domain and domain not in enrichment_results["domains"]:
            age_days = get_domain_age(domain)
            vt_info = check_virustotal_url(url)
            
            enrichment_results["domains"][domain] = {
                "age_days": age_days,
                "vt_malicious": vt_info.get("malicious", 0),
                "vt_status": vt_info.get("vt_status", "success")
            }

    # --- RÈGLES ---
    rules_triggered = []
    
    has_pressure, pressure_count = check_pressure_words(subject, full_content)
    if has_pressure:
        rules_triggered.append({"rule": "pressure_words", "points": 5, "reason": f"{pressure_count} mots de pression détectés (+5)"})

    domains_to_check = [urlparse(u).hostname for u in found_urls]
    if '@' in email_addr:
        domains_to_check.append(email_addr.split('@')[1])

    for domain in domains_to_check:
        if not domain:
            continue
        is_spoofed, brand = check_typosquatting(domain)
        if is_spoofed:
            rules_triggered.append({"rule": "lookalike_domain", "points": 15, "reason": f"Le domaine {domain} imite la marque {brand} (+15)"})
            break

    for att in attachments:
        is_risky, ext, is_double = check_risky_attachment(att["filename"])
        if is_risky:
            rules_triggered.append({"rule": "risky_attachment", "points": 10, "reason": f"Pièce jointe suspecte ({att['filename']}) (+10)"})
        
        if att.get("vt_malicious", 0) >= 5:
            rules_triggered.append({"rule": "known_malware", "points": 40, "reason": f"Pièce jointe connue comme malware : {att['vt_malicious']} moteurs VT (+40)"})

    if "spf=fail" in auth_results.lower() or "dkim=fail" in auth_results.lower():
        rules_triggered.append({"rule": "auth_fail", "points": 15, "reason": "Échec SPF ou DKIM dans les en-têtes (+15)"})

    if raw_reply_to != 'N/A' and email_addr not in raw_reply_to:
        rules_triggered.append({"rule": "reply_to_mismatch", "points": 10, "reason": "Reply-To différent de l'expéditeur From (+10)"})

    return {
        "subject": subject,
        "from_name": name,
        "from_address": email_addr,
        "reply_to": raw_reply_to,
        "return_path": return_path,
        "authentication_results": auth_results,
        "urls": found_urls,
        "attachments": attachments,
        "enrichment": enrichment_results,
        "rules_triggered": rules_triggered
    }

@app.post("/block")
async def block_indicators(payload: BlockRequest):
    os.makedirs("blocklist", exist_ok=True)
    file_path = "blocklist/domains.txt"
    
    existing_domains = set()
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            existing_domains = set(line.strip() for line in f if line.strip())
            
    added = []
    for d in payload.domains:
        d_lower = d.lower()
        if d_lower not in ALLOWLIST and d_lower not in existing_domains:
            existing_domains.add(d_lower)
            added.append(d_lower)
            
    with open(file_path, "w") as f:
        for d in sorted(existing_domains):
            f.write(f"{d}\n")
            
    return {
        "status": "success",
        "added_domains": added,
        "total_blocked": len(existing_domains)
    }