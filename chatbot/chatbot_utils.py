import google.generativeai as genai
import os
import logging
import time
import textwrap
from google.api_core.exceptions import GoogleAPIError

# Configuration du logger
logger = logging.getLogger(__name__)

# Charger la clé API
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    logger.error("Clé API Google non définie.")
    raise ValueError("Clé API manquante.")

genai.configure(api_key=api_key)
logger.info("Clé API Google configurée avec succès.")

# Liste des sujets de cybersécurité
cybersecurity_topics = list(set([
    "sécurité des réseaux Wi-Fi", "attaques par déni de service (DDoS)", "injection SQL",
    "botnets", "chiffrement des données", "protection contre les malwares", "sécurité réseau",
    "firewall", "pentest", "malware", "phishing", "ransomware", "cryptographie",
    "hacking", "piratage", "vulnérabilités", "forensics", "cyberattaque",
    "cyberdéfense", "ingénierie sociale", "sécurité cloud", "sécurité IoT", "VPN", "SSL", "TLS",
    "sécurité des bases de données", "authentification multi-facteurs", "MITM (Man-In-The-Middle)",
    "sécurité des réseaux Wi-Fi", "attaques par déni de service (DDoS)", "injection SQL",
    "botnets", "failles zero-day", "chiffrement des données", "protection contre les malwares",
    "sécurité des mots de passe", "authentification multi-facteurs", "pare-feu", "réseau",
    "wi-fi", "wifi", "réseau wi-fi", "réseau wifi", "sécurité réseau", "sécurité wi-fi",
    "protection réseau", "sécuriser réseau", "sécuriser wi-fi", "sécurité informatique",
    "sécurité des réseaux Wi-Fi", "attaques par déni de service (DDoS)", "injection SQL",
    "botnets", "failles zero-day", "chiffrement des données", "protection contre les malwares",
    "sécurité des mots de passe", "authentification multi-facteurs", "pare-feu",
    "détection d'intrusion", "prévention d'intrusion", "analyse de risques",
    "sécurité des applications web", "sécurité des données personnelles", 
    "cybercriminalité", "cyberattaque", "cyberdéfense", "cyberterrorisme",
    "vulnérabilités logicielles", "ingénierie sociale", "phishing", "ransomware",
    "sécurité cloud", "sécurité IoT", "sécurité des transactions en ligne",
    "sécurité informatique", "cyber", "hacking", "hack", "hacker", "cybersécurité", "pentest", "firewall",
    "malware", "phishing", "ransomware", "cryptographie", "attaque", "piratage", "sécurité réseau", "protection des données", 
    "vulnérabilité", "intrusion", "détection d'intrusion", "prévention d'intrusion", "analyse de malware", "sécurité des applications", 
    "sécurité web", "sécurité mobile", "sécurité cloud", "sécurité des objets connectés", "IoT", "chiffrement", "authentification", 
    "autorisation", "virus", "ver", "cheval de Troie", "gestion des identités", "audit de sécurité", "test de pénétration", "analyse de risques", "plan de réponse aux incidents", 
    "forensics", "informatique légale", "cybercriminalité", "cyberattaque", "cyberdéfense", "cyberterrorisme", "virus", 
    "cheval de troie", "ver informatique", "spyware", "adware", "rootkit", "keylogger", "logiciel espion", "déni de service", 
    "DDoS", "injection SQL", "cross-site scripting", "usurpation d'identité", "RGPD", "ISO 27001", "sécurité physique", 
    "sécurité logique", "sécurité des systèmes d'information", "SSI", "gestion des vulnérabilités", "sécurité des terminaux", 
    "antivirus", "IDS", "IPS", "SIEM", "SOC", "veille de sécurité", "CERT", "honeypot", "bug bounty", "sécurité des communications", 
    "VPN", "SSL", "TLS", "sécurité des bases de données", "sécurité du Wi-Fi", "sécuriser un réseau wifi", "sécurité des mots de passe", 
    "authentification multi-facteurs", "biométrie", "MITM (Man-In-The-Middle)", "Man-In-The-Middle", "sécurité des transactions", "blockchain", "cyber résilience", 
    "menace persistante avancée", "APT", "Dark Web", "deepfake", "arnaque en ligne", "hameçonnage", "rançongiciel", 
    "logiciel malveillant", "faille de sécurité", "pirate informatique", "sécurité des réseaux sans fil", "sécurité des systèmes embarqués", 
    "exploit", "sécurité", "Dark Web", "rootkit", "VPN", "SSL", "SSI", "TLS", "IPS", "IDS", "sécurisation wifi",
    "SSL/TLS", "routeur", "ips", "ids", "hachage", "routeur", "switch", "serveur", "vlan", "OWASP Top 10", "chiffrement asymétrique",
    "cybersécurité", "cybersecurite", "cybersécurite", "IDS", "IPS", "SIEM", "SOC", "hachage", "hach", "cia", "CIA", 'cid', "CID",
    "confidentialité", "confidentialite", "intégrité", "disponibilité", "integrite", "disponibilite",
    # Ajoutez d'autres sujets pertinents.
]))



FAQ_RESPONSES = {
    "comment t'appelles-tu": "Je suis **chatBot**, un assistant spécialisé en cybersécurité.",
    "pourquoi est-il important de mettre à jour mon routeur": "Mettre à jour votre routeur corrige les failles de sécurité et améliore les performances.",
}


def is_security_related(question):
    """ Vérifie si la question est liée à la sécurité informatique """
    question_lower = question.lower()
    return any(keyword in question_lower for keyword in cybersecurity_topics)


def send_message_to_gemini(user_message):
    """Envoie un message à Gemini en utilisant la similarité sémantique."""
    if not api_key:
        return "Erreur d'authentification avec l'API Gemini. Clé API manquante."

    # Vérification des questions générales
    user_message_lower = user_message.lower().strip()
    if user_message_lower in FAQ_RESPONSES:
        return FAQ_RESPONSES[user_message_lower]

    # Vérifier si la question concerne la cybersécurité
    if not is_security_related(user_message):
        return "Je suis un chatbot spécialisé en sécurité informatique. Pose-moi une question en rapport avec ce domaine ! 😊"

    prompt_personnalisation = """
    Tu es un expert en cybersécurité. Réponds de manière technique et détaillée aux questions concernant la sécurité des réseaux, les menaces informatiques et les meilleures pratiques de cybersécurité. 
    Exemple : "Comment fonctionne le chiffrement asymétrique ?", "Quelles sont les dernières vulnérabilités zero-day ?", "Comment analyser un fichier malware ?"
    """

    try:
        model_gemini = genai.GenerativeModel('gemini-1.5-pro')
        logger.info("Modèle Gemini chargé avec succès.")
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation du modèle Gemini : {e}")
        return "Impossible de charger le modèle Gemini."

    retries = 0
    max_retries = 2

    while retries < max_retries:
        try:
            réponse = model_gemini.generate_content(prompt_personnalisation + "\n\n" + user_message)
            if réponse and hasattr(réponse, 'text') and réponse.text:
                return textwrap.shorten(réponse.text.strip(), width=500, placeholder="...")
            else:
                return "Le chatbot n'a pas pu générer de réponse."
        except GoogleAPIError as e:
            logger.error(f"Erreur API Gemini: {e}")
            retries += 1
            time.sleep(1)
        except Exception as e:
            logger.error(f"Erreur inattendue : {e}")
            return "Une erreur inattendue est survenue. Veuillez réessayer plus tard."

    return "L'API Gemini est temporairement surchargée. Veuillez réessayer plus tard."
