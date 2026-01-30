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
                "I apologize, but I'm experiencing technical difficulties at the moment. Please try again shortly, or contact our support team if the issue persists.",
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
        
        if (sender === 'bot' && !isError) {
            const label = document.createElement('strong');
            label.textContent = 'WebShield Assistant';
            contentDiv.appendChild(label);
        }
        
        if (sender === 'bot' && !isError) {
            const parts = this.splitSources(text);
            const bodyP = document.createElement('p');
            bodyP.innerHTML = this.formatMessage(parts.body);
            contentDiv.appendChild(bodyP);

            if (parts.sources.length > 0) {
                const sourcesDiv = document.createElement('div');
                sourcesDiv.className = 'message-sources';

                const sourcesTitle = document.createElement('div');
                sourcesTitle.className = 'sources-title';
                sourcesTitle.textContent = 'Sources';
                sourcesDiv.appendChild(sourcesTitle);

                const sourcesList = document.createElement('ul');
                sourcesList.className = 'sources-list';
                parts.sources.forEach((s) => {
                    const li = document.createElement('li');
                    li.textContent = s;
                    sourcesList.appendChild(li);
                });
                sourcesDiv.appendChild(sourcesList);
                contentDiv.appendChild(sourcesDiv);
            }
        } else {
            const textP = document.createElement('p');
            textP.innerHTML = this.formatMessage(text);
            contentDiv.appendChild(textP);
        }
        
        if (isError) {
            contentDiv.classList.add('error-message');
        }
        
        messageDiv.appendChild(contentDiv);
        this.messagesContainer.appendChild(messageDiv);
        
        // Scroll to bottom
        this.scrollToBottom();
    }

    formatMessage(text) {
        let formatted = this.escapeHtml(String(text ?? ''));

        formatted = formatted.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        formatted = formatted.replace(/(^|[^\*])\*(?!\s)(.+?)(?<!\s)\*(?!\*)/g, '$1<em>$2</em>');
        formatted = formatted.replace(/`([^`]+?)`/g, '<code>$1</code>');
        formatted = formatted.replace(/\n/g, '<br>');
        formatted = formatted.replace(/(^|<br>)\s*[-*]\s+/g, '$1• ');
        return formatted;
    }

    escapeHtml(s) {
        return s
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    splitSources(text) {
        const raw = String(text ?? '');
        const match = raw.match(/\n?Sources:\s*([\s\S]*)$/i);
        if (!match) {
            return { body: raw, sources: [] };
        }
        const body = raw.slice(0, match.index).trim();
        const tail = (match[1] || '').trim();
        const sources = tail
            .split(/\r?\n/)
            .map((l) => l.replace(/^[-•\s]+/, '').trim())
            .filter(Boolean);
        return { body, sources };
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
        
        // Limit to 6 suggestions for better UX
        const displaySuggestions = suggestions.slice(0, 6);
        
        displaySuggestions.forEach(suggestion => {
            const btn = document.createElement('button');
            btn.className = 'suggestion-btn';
            btn.dataset.message = suggestion;
            
            // Add emoji based on content
            let emoji = '💡';
            if (suggestion.toLowerCase().includes('phishing')) emoji = '🎣';
            else if (suggestion.toLowerCase().includes('scan')) emoji = '🔍';
            else if (suggestion.toLowerCase().includes('score')) emoji = '📊';
            else if (suggestion.toLowerCase().includes('accurate') || suggestion.toLowerCase().includes('ai')) emoji = '🎯';
            else if (suggestion.toLowerCase().includes('feature')) emoji = '⚡';
            else if (suggestion.toLowerCase().includes('ssl')) emoji = '🔒';
            else if (suggestion.toLowerCase().includes('extension')) emoji = '🧩';
            else if (suggestion.toLowerCase().includes('detect')) emoji = '🛡️';
            
            btn.textContent = `${emoji} ${suggestion}`;
            
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
