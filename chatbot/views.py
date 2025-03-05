from django.shortcuts import render
import json
import logging
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from chatbot.chatbot_utils import send_message_to_gemini, FAQ_RESPONSES  # Ajout de l'import
import re
import unicodedata

# Configuration du logger
logger = logging.getLogger(__name__)

def normalize_question(question):
    """Normalise la question en minuscules, supprime la ponctuation et normalise les accents."""
    question = question.lower()
    question = re.sub(r'[^\w\s]', '', question)
    question = ''.join(c for c in unicodedata.normalize('NFD', question) if unicodedata.category(c) != 'Mn')
    return question.strip()

# Vue du chatbot
@require_POST
def chatbot_api(request):
    try:
        data = json.loads(request.body)
        user_message = data.get("message")

        if not user_message or not isinstance(user_message, str):
            logger.warning("Requête invalide : message utilisateur manquant ou incorrect.")
            return JsonResponse({"error": "Requête invalide"}, status=400)

        logger.info(f"Message reçu : {user_message}")

        # Normalisation de la question de l'utilisateur
        user_message_normalized = normalize_question(user_message)

        # Vérification des questions générales normalisées
        for question, response in FAQ_RESPONSES.items():
            if normalize_question(question) == user_message_normalized:
                return JsonResponse({"response": response})

        response = send_message_to_gemini(user_message)  # Appel à l'API Gemini

        if not response or not isinstance(response, str):
            logger.error("Réponse invalide de l'API Gemini.")
            return JsonResponse({"error": "Erreur lors de la génération de la réponse"}, status=500)

        logger.info(f"Réponse de Gemini : {response}")

        return JsonResponse({"response": response})

    except json.JSONDecodeError:
        logger.warning("Erreur de décodage JSON dans la requête.")
        return JsonResponse({"error": "Requête invalide"}, status=400)

    except Exception as e:
        logger.exception(f"Erreur inattendue dans la vue chatbot_api : {e}")
        return JsonResponse({"error": "Erreur interne du serveur"}, status=500)

def index(request):
    return render(request, 'chatbot.html')
