document.addEventListener('DOMContentLoaded', function () {
    const chatbotToggle = document.getElementById('chatbot-toggle');
    const chatbotContainer = document.getElementById('chatbot-container');
    const chatbotInput = document.getElementById('chatbot-input');
    const chatbotMessages = document.getElementById('chatbot-messages');
    const chatbotForm = document.getElementById('chatbot-form');

    // Mostrar/Ocultar chatbot
    chatbotToggle.addEventListener('click', function () {
        chatbotContainer.classList.toggle('chatbot-hidden');
    });

    // Enviar mensaje al chatbot
    chatbotForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        const userMessage = chatbotInput.value.trim();
        if (!userMessage) return;

        // Agregar mensaje del usuario a la interfaz
        const userMessageElem = document.createElement('div');
        userMessageElem.classList.add('chatbot-message', 'user');
        userMessageElem.textContent = userMessage;
        chatbotMessages.appendChild(userMessageElem);

        chatbotInput.value = ''; // Limpiar el campo de entrada

        // Simular respuesta del chatbot (lógica básica o conectar a Flask)
        try {
            const response = await fetch('/chatbot', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: userMessage }),
            });
            const data = await response.json();

            const botMessageElem = document.createElement('div');
            botMessageElem.classList.add('chatbot-message', 'bot');
            botMessageElem.textContent = data.response;
            chatbotMessages.appendChild(botMessageElem);
        } catch (error) {
            const errorElem = document.createElement('div');
            errorElem.classList.add('chatbot-message', 'bot');
            errorElem.textContent = 'Hubo un error. Intenta más tarde.';
            chatbotMessages.appendChild(errorElem);
        }

        // Scroll hacia abajo
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
    });
});
