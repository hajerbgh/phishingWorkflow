import os
import re
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

def extract_urls(text):
    # Regex simple pour attraper les URLs HTTP/HTTPS
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return list(set(re.findall(url_pattern, text)))

def parse_eml(file_path):
    print(f"\n--- ANALYSE DU FICHIER : {file_path} ---")
    
    if not os.path.exists(file_path):
        print(f"Erreur : Le fichier {file_path} est introuvable.")
        return

    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # 1. Extraction des en-têtes principaux
    subject = msg.get('Subject', 'N/A')
    raw_from = msg.get('From', 'N/A')
    raw_reply_to = msg.get('Reply-To', 'N/A')
    return_path = msg.get('Return-Path', 'N/A')
    auth_results = msg.get('Authentication-Results', 'N/A')

    name, email_addr = parseaddr(raw_from)

    print(f"Sujet      : {subject}")
    print(f"From       : Nom='{name}' | Adresse='{email_addr}'")
    print(f"Reply-To   : {raw_reply_to}")
    print(f"Return-Path: {return_path}")

    # 2. Analyse de l'Authentication-Results
    print(f"\n[Sécurité & Authentification]")
    print(f"Authentication-Results bruts : {auth_results}")
    
    # 3. Extraction du Corps et des URLs
    body_text = ""
    body_html = ""

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get('Content-Disposition', ''))

        # Ignorer les pièces jointes pour le corps
        if 'attachment' in content_disposition:
            continue

        try:
            payload = part.get_payload(decode=True)
            if payload:
                decoded_content = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                if content_type == 'text/plain':
                    body_text += decoded_content
                elif content_type == 'text/html':
                    body_html += decoded_content
        except Exception as e:
            pass

    full_content = body_text + " " + body_html
    found_urls = extract_urls(full_content)

    print(f"\n[URLs détectées ({len(found_urls)})]")
    for url in found_urls:
        print(f" - {url}")

    # 4. Analyse des Pièces Jointes
    print(f"\n[Pièces jointes]")
    attachment_count = 0
    for part in msg.iter_attachments():
        attachment_count += 1
        filename = part.get_filename() or "inconnu"
        file_type = part.get_content_type()
        file_data = part.get_payload(decode=True)
        file_size = len(file_data) if file_data else 0
        
        sha256_hash = "N/A"
        if file_data:
            sha256_hash = hashlib.sha256(file_data).hexdigest()

        print(f" - Nom : {filename}")
        print(f"   Type  : {file_type}")
        print(f"   Taille: {file_size} octets")
        print(f"   SHA256: {sha256_hash}")

    if attachment_count == 0:
        print(" Aucune pièce jointe trouvée.")

if __name__ == "__main__":
    # Teste ton script sur tes futurs fichiers .eml
    parse_eml("samples/phish1.eml")