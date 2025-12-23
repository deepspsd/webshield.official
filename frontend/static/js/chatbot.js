/**
 * WebShield Chatbot Assistant
 * AI-powered help system for users
 */

class ChatbotAssistant {
    constructor() {
        this.messagesContainer = document.getElementById('chatMessages');
        this.chatInput = document.getElementById('chatInput');
        this.sendBtn = document.getElementById('sendBtn');
        this.suggestionsContainer = document.getElementById('suggestions');
        
        this.apiBase = window.location.origin;
        this.conversationHistory = [];
        
        this.init();
    }

    init() {
        // Event listeners
        this.sendBtn.addEventListener('click', () => this.sendMessage());
        this.chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Suggestion buttons
        document.querySelectorAll('.suggestion-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const message = btn.dataset.message;
                this.chatInput.value = message;
                this.sendMessage();
            });
        });

        // Auto-focus input
        this.chatInput.focus();
    }

    async sendMessage() {
        const message = this.chatInput.value.trim();
        
        if (!message) return;

        // Disable input while processing
        this.setInputState(false);

        // Add user message to chat
        this.addMessage(message, 'user');
        
        // Clear input
        this.chatInput.value = '';

        // Show typing indicator
        this.showTypingIndicator();

        try {
            // Send to API
            const response = await fetch(`${this.apiBase}/api/chatbot/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    message: message,
                    context: this.getContext()
                })
            });

            if (!response.ok) {
                throw new Error('Failed to get response');
            }

            const data = await response.json();

            // Remove typing indicator
            this.hideTypingIndicator();

            // Add bot response
            this.addMessage(data.response, 'bot');

            // Update suggestions if provided
            if (data.suggestions && data.suggestions.length > 0) {
                this.updateSuggestions(data.suggestions);
            }

            // Store in conversation history
            this.conversationHistory.push({
                user: message,
                bot: data.response,
                timestamp: data.timestamp
            });

        } catch (error) {
            console.error('Chatbot error:', error);
            this.hideTypingIndicator();
            this.addMessage(
                "I'm sorry, I'm having trouble responding right now. Please try again in a moment.",
                'bot',
                true
            );
        } finally {
            // Re-enable input
            this.setInputState(true);
            this.chatInput.focus();
        }
    }

    addMessage(text, sender, isError = false) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        
        if (sender === 'bot') {
            const label = document.createElement('strong');
            label.textContent = 'WebShield Assistant:';
            contentDiv.appendChild(label);
        }
        
        const textP = document.createElement('p');
        textP.innerHTML = this.formatMessage(text);
        contentDiv.appendChild(textP);
        
        if (isError) {
            contentDiv.classList.add('error-message');
        }
        
        messageDiv.appendChild(contentDiv);
        this.messagesContainer.appendChild(messageDiv);
        
        // Scroll to bottom
        this.scrollToBottom();
    }

    formatMessage(text) {
        // Convert markdown-style formatting to HTML
        let formatted = text;
        
        // Bold text
        formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        
        // Italic text
        formatted = formatted.replace(/\*(.*?)\*/g, '<em>$1</em>');
        
        // Code blocks
        formatted = formatted.replace(/`(.*?)`/g, '<code>$1</code>');
        
        // Line breaks
        formatted = formatted.replace(/\n/g, '<br>');
        
        return formatted;
    }

    showTypingIndicator() {
        const typingDiv = document.createElement('div');
        typingDiv.className = 'message bot-message';
        typingDiv.id = 'typingIndicator';
        
        const indicator = document.createElement('div');
        indicator.className = 'typing-indicator';
        indicator.innerHTML = '<span></span><span></span><span></span>';
        
        typingDiv.appendChild(indicator);
        this.messagesContainer.appendChild(typingDiv);
        
        this.scrollToBottom();
    }

    hideTypingIndicator() {
        const indicator = document.getElementById('typingIndicator');
        if (indicator) {
            indicator.remove();
        }
    }

    updateSuggestions(suggestions) {
        this.suggestionsContainer.innerHTML = '';
        
        suggestions.forEach(suggestion => {
            const btn = document.createElement('button');
            btn.className = 'suggestion-btn';
            btn.dataset.message = suggestion;
            btn.textContent = suggestion;
            
            btn.addEventListener('click', () => {
                this.chatInput.value = suggestion;
                this.sendMessage();
            });
            
            this.suggestionsContainer.appendChild(btn);
        });
    }

    getContext() {
        // Get context from URL params or localStorage
        const urlParams = new URLSearchParams(window.location.search);
        const scanId = urlParams.get('scan_id');
        
        if (scanId) {
            // Try to get scan data from localStorage
            const scanData = localStorage.getItem(`scan_${scanId}`);
            if (scanData) {
                return { scan_result: JSON.parse(scanData) };
            }
        }
        
        return null;
    }

    setInputState(enabled) {
        this.chatInput.disabled = !enabled;
        this.sendBtn.disabled = !enabled;
    }

    scrollToBottom() {
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }
}

// Initialize chatbot when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new ChatbotAssistant();
});

// Export for use in other scripts
window.ChatbotAssistant = ChatbotAssistant;
