import smtplib
from email.message import EmailMessage

def send(subject, sender, body, reply_to=None, auth=None):
    m = EmailMessage()
    m['Subject'], m['From'], m['To'] = subject, sender, "phishing-report@lab.local"
    if reply_to: m['Reply-To'] = reply_to
    if auth: m['Authentication-Results'] = auth
    m.set_content(body)
    with smtplib.SMTP('localhost', 1025) as s:
        s.send_message(m)
    print("envoyé :", subject)

# 1. Typosquatting + Reply-To + SPF fail  -> MALICIOUS
send("URGENT : Suspension imminente de votre accès sécurisé",
     "security@societegenerale-alerte.local",
     "Validez votre identité de manière immédiate :\nhttps://login.societegenerale-securite-urgent.xyz/connexion",
     reply_to="attaquant@evil.com", auth="mx.lab.local; spf=fail; dkim=fail")

# 2. Faux domaine + mots de pression, sans pièce jointe -> SUSPICIOUS
send("Action requise : vérifiez votre compte",
     "support@paypa1-secure.local",
     "Votre compte nécessite une vérification urgente. Merci de vérifier vos informations.")

# 3. Mail légitime -> BENIGN
send("Compte rendu de la réunion de lundi",
     "collegue@lab.local",
     "Bonjour, voici le compte rendu de la réunion. Bonne journée.")

# 4. Mail légitime avec lien allowlisté -> BENIGN
send("Invitation Google Meet",
     "calendar@google.com",
     "Rejoignez la réunion : https://meet.google.com/abc-defg-hij")