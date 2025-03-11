document.addEventListener("DOMContentLoaded", function () {
    // Permet d'envoyer un message en appuyant sur "Entrée"
    document.getElementById("userInput").addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            sendMessage();
        }
    });
});

let questionEnAttente = false; // Variable pour bloquer les nouvelles questions en attente de réponse

// Fonction pour envoyer un message
function sendMessage() {
    let userInput = document.getElementById("userInput").value.trim();

    if (userInput === "") return; // Empêche d'envoyer un message vide
    if (questionEnAttente) {
        alert("Veuillez attendre la réponse avant de poser une autre question.");
        return;
    }

    questionEnAttente = true; // Bloque l'envoi de nouvelles questions
    console.log("Message saisi :", userInput);

    displayMessage(userInput, "user"); // Affichage du message utilisateur
    document.getElementById("userInput").value = ""; // Efface l'input après envoi

    // Ajouter le chargement directement dans le chatbox
    let loadingId = "loading-" + new Date().getTime(); // ID unique pour le spinner
    displayLoading(loadingId);

    // Envoi du message à l'API render
    fetch('https://chatbot-cybersecurite-cfg8.onrender.com/api/chat/', {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken") // Gestion du token CSRF si nécessaire
        },
        body: JSON.stringify({ message: userInput })
    })
    .then(response => response.json())
    .then(data => {
        console.log("Réponse reçue :", data);

        // Supprimer le spinner de chargement
        removeLoading(loadingId);

        if (data.response) {
            displayMessage(data.response, "bot");
        } else if (data.error) {
            displayMessage("Erreur : " + data.error, "bot");
        } else {
            displayMessage("Erreur : réponse inattendue du serveur", "bot");
        }

        questionEnAttente = false; // Débloque l'envoi après réception de la réponse
    })
    .catch(error => {
        console.error("Erreur serveur :", error);
        removeLoading(loadingId);
        displayMessage("Erreur serveur : " + error.message, "bot");
        questionEnAttente = false; // Débloque l'envoi même en cas d'erreur
    });
}

// Fonction pour afficher un message dans le chatbox
function displayMessage(message, sender) {
    let chatbox = document.getElementById("chatbox");

    if (!chatbox) {
        console.error("L'élément #chatbox est introuvable !");
        return;
    }

    let msgDiv = document.createElement("div");
    msgDiv.classList.add("message", sender === "user" ? "user-message" : "bot-message");
    msgDiv.textContent = message;

    chatbox.appendChild(msgDiv);

    // Faire défiler vers le bas pour voir le dernier message
    chatbox.scrollTop = chatbox.scrollHeight;
}

// Fonction pour afficher le chargement dans le chatbox
function displayLoading(loadingId) {
    let chatbox = document.getElementById("chatbox");

    let loadingDiv = document.createElement("div");
    loadingDiv.id = loadingId;
    loadingDiv.classList.add("bot-message");

    loadingDiv.innerHTML = `
        <strong>Chatbot:</strong> 
        <span class="spinner-border text-primary spinner-border-sm"></span> 
        <span class="text-muted">En train d'écrire...</span>
    `;

    chatbox.appendChild(loadingDiv);
    chatbox.scrollTop = chatbox.scrollHeight;
}

// Fonction pour supprimer le chargement du chatbox
function removeLoading(loadingId) {
    let loadingElement = document.getElementById(loadingId);
    if (loadingElement) {
        loadingElement.remove();
    }
}

// Fonction pour récupérer le token CSRF (si Django CSRF activé)
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== "") {
        let cookies = document.cookie.split(";");
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i].trim();
            if (cookie.startsWith(name + "=")) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
