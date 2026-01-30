/**
 * WebShield Chatbot Widget
 * Floating chatbot that can be embedded on any page
 */

class ChatbotWidget {
    constructor() {
        console.log('🤖 ChatbotWidget constructor called');
        this.isOpen = false;
        this.apiBase = window.location.origin;
        this.conversationHistory = [];
        
        this.createWidget();
        this.init();
        console.log('✅ ChatbotWidget initialized successfully');
    }

    createWidget() {
        console.log('🔨 Creating chatbot widget HTML...');
        // Create widget HTML
        const widgetHTML = `
            <div id="chatbot-widget" class="chatbot-widget">
                <!-- Chat button -->
                <div class="chatbot-toggle-container">
                    <div class="chatbot-tooltip" id="chatbot-tooltip">
                        💬 Chat with WebShield AI
                    </div>
                    <button id="chatbot-toggle" class="chatbot-toggle" aria-label="Open chat assistant">
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        <span class="notification-badge" id="chatbot-badge" style="display: none;">1</span>
                    </button>
                </div>

                <!-- Chat window -->
                <div id="chatbot-window" class="chatbot-window" style="display: none;">
                    <div class="chatbot-header">
                        <div class="chatbot-header-content">
                            <h3>🤖 WebShield Assistant</h3>
                            <p>Ask me anything!</p>
                        </div>
                        <button id="chatbot-close" class="chatbot-close" aria-label="Close chat">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M18 6L6 18M6 6l12 12" stroke-width="2" stroke-linecap="round"/>
                            </svg>
                        </button>
                    </div>

                    <div class="chatbot-messages" id="chatbot-messages">
                        <div class="message bot-message">
                            <div class="message-content">
                                <p>👋 Hi! I'm your WebShield assistant. How can I help you today?</p>
                            </div>
                        </div>
                    </div>

                    <div class="chatbot-quick-actions" id="chatbot-quick-actions">
                        <button class="quick-action-btn" data-message="How does WebShield work?">
                            🛡️ How it works
                        </button>
                        <button class="quick-action-btn" data-message="What is phishing?">
                            🎣 What is phishing?
                        </button>
                        <button class="quick-action-btn" data-message="How do I scan a URL for threats?">
                            🔍 Scan URLs
                        </button>
                    </div>

                    <div class="chatbot-input-area">
                        <input 
                            type="text" 
                            id="chatbot-input" 
                            placeholder="Type your question..." 
                            maxlength="500"
                        >
                        <button id="chatbot-send" class="chatbot-send-btn">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add to body
        console.log('📝 Adding widget HTML to body...');
        document.body.insertAdjacentHTML('beforeend', widgetHTML);
        console.log('✅ Widget HTML added to body');

        // Add styles
        this.addStyles();
    }

    addStyles() {
        console.log('🎨 Adding widget styles...');
        const styles = `
            <style>
                .chatbot-widget {
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    z-index: 9999;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                }

                .chatbot-toggle-container {
                    position: relative;
                    display: inline-block;
                }

                .chatbot-tooltip {
                    position: absolute;
                    bottom: 75px;
                    right: 0;
                    background: rgba(17, 24, 39, 0.95);
                    color: white;
                    padding: 12px 20px;
                    border-radius: 12px;
                    font-size: 14px;
                    font-weight: 500;
                    white-space: nowrap;
                    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
                    opacity: 0;
                    visibility: hidden;
                    transition: all 0.3s ease;
                    pointer-events: none;
                }

                .chatbot-tooltip::after {
                    content: '';
                    position: absolute;
                    bottom: -6px;
                    right: 20px;
                    width: 12px;
                    height: 12px;
                    background: rgba(17, 24, 39, 0.95);
                    transform: rotate(45deg);
                }

                .chatbot-toggle-container:hover .chatbot-tooltip {
                    opacity: 1;
                    visibility: visible;
                    bottom: 80px;
                }

                .chatbot-toggle {
                    width: 64px;
                    height: 64px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
                    border: none;
                    color: white;
                    cursor: pointer;
                    box-shadow: 0 4px 20px rgba(255, 107, 53, 0.4);
                    transition: all 0.3s ease;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    position: relative;
                    animation: pulse 2s infinite;
                }

                @keyframes pulse {
                    0%, 100% {
                        box-shadow: 0 4px 20px rgba(255, 107, 53, 0.4);
                    }
                    50% {
                        box-shadow: 0 4px 30px rgba(255, 107, 53, 0.6), 0 0 0 8px rgba(255, 107, 53, 0.1);
                    }
                }

                .chatbot-toggle:hover {
                    transform: scale(1.1);
                    box-shadow: 0 6px 30px rgba(255, 107, 53, 0.6);
                    animation: none;
                }

                .notification-badge {
                    position: absolute;
                    top: -5px;
                    right: -5px;
                    background: #ef4444;
                    color: white;
                    border-radius: 50%;
                    width: 24px;
                    height: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 12px;
                    font-weight: bold;
                }

                .chatbot-window {
                    position: absolute;
                    bottom: 80px;
                    right: 0;
                    width: 380px;
                    height: 550px;
                    background: rgba(17, 24, 39, 0.95);
                    backdrop-filter: blur(10px);
                    border-radius: 16px;
                    box-shadow: 0 8px 40px rgba(0, 0, 0, 0.5);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    display: flex;
                    flex-direction: column;
                    animation: slideUp 0.3s ease-out;
                }

                @keyframes slideUp {
                    from {
                        opacity: 0;
                        transform: translateY(20px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }

                .chatbot-header {
                    padding: 1.25rem;
                    background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
                    border-radius: 16px 16px 0 0;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }

                .chatbot-header-content h3 {
                    margin: 0;
                    font-size: 1.1rem;
                    color: white;
                }

                .chatbot-header-content p {
                    margin: 0.25rem 0 0 0;
                    font-size: 0.85rem;
                    color: rgba(255, 255, 255, 0.8);
                }

                .chatbot-close {
                    background: rgba(255, 255, 255, 0.2);
                    border: none;
                    color: white;
                    width: 32px;
                    height: 32px;
                    border-radius: 8px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    transition: background 0.2s;
                }

                .chatbot-close:hover {
                    background: rgba(255, 255, 255, 0.3);
                }

                .chatbot-messages {
                    flex: 1;
                    overflow-y: auto;
                    padding: 1rem;
                    scroll-behavior: smooth;
                }

                .chatbot-messages::-webkit-scrollbar {
                    width: 6px;
                }

                .chatbot-messages::-webkit-scrollbar-track {
                    background: rgba(255, 255, 255, 0.05);
                }

                .chatbot-messages::-webkit-scrollbar-thumb {
                    background: rgba(99, 102, 241, 0.5);
                    border-radius: 3px;
                }

                .message {
                    margin-bottom: 1rem;
                    animation: fadeIn 0.3s ease-out;
                }

                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(5px); }
                    to { opacity: 1; transform: translateY(0); }
                }

                .message-content {
                    padding: 0.75rem 1rem;
                    border-radius: 12px;
                    max-width: 85%;
                    font-size: 0.9rem;
                    line-height: 1.5;
                }

                .user-message .message-content {
                    background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
                    margin-left: auto;
                    color: white;
                }

                .bot-message .message-content {
                    background: rgba(255, 255, 255, 0.1);
                    color: #e2e8f0;
                }

                .message-sources {
                    margin-top: 0.75rem;
                    padding: 0.65rem 0.75rem;
                    border-radius: 12px;
                    background: rgba(255, 255, 255, 0.06);
                    border: 1px solid rgba(255, 255, 255, 0.12);
                }

                .sources-title {
                    font-size: 0.72rem;
                    font-weight: 700;
                    letter-spacing: 0.06em;
                    text-transform: uppercase;
                    color: rgba(255, 255, 255, 0.65);
                    margin-bottom: 0.35rem;
                }

                .sources-list {
                    margin: 0;
                    padding-left: 1rem;
                }

                .sources-list li {
                    margin: 0.2rem 0;
                    color: rgba(255, 255, 255, 0.65);
                    word-break: break-word;
                }

                .chatbot-quick-actions {
                    padding: 0.75rem 1rem;
                    display: flex;
                    gap: 0.5rem;
                    flex-wrap: wrap;
                    border-top: 1px solid rgba(255, 255, 255, 0.1);
                }

                .quick-action-btn {
                    padding: 0.5rem 0.75rem;
                    background: rgba(99, 102, 241, 0.2);
                    border: 1px solid rgba(99, 102, 241, 0.4);
                    border-radius: 12px;
                    color: #c7d2fe;
                    font-size: 0.8rem;
                    cursor: pointer;
                    transition: all 0.2s;
                }

                .quick-action-btn:hover {
                    background: rgba(99, 102, 241, 0.4);
                    transform: translateY(-1px);
                }

                .chatbot-input-area {
                    padding: 1rem;
                    display: flex;
                    gap: 0.5rem;
                    border-top: 1px solid rgba(255, 255, 255, 0.1);
                }

                #chatbot-input {
                    flex: 1;
                    padding: 0.75rem;
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    border-radius: 10px;
                    color: white;
                    font-size: 0.9rem;
                }

                #chatbot-input:focus {
                    outline: none;
                    border-color: #818cf8;
                }

                #chatbot-input::placeholder {
                    color: rgba(255, 255, 255, 0.4);
                }

                .chatbot-send-btn {
                    width: 40px;
                    height: 40px;
                    background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
                    border: none;
                    border-radius: 10px;
                    color: white;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    transition: all 0.2s;
                }

                .chatbot-send-btn:hover {
                    transform: scale(1.05);
                    box-shadow: 0 4px 12px rgba(255, 107, 53, 0.4);
                }

                .chatbot-send-btn:disabled {
                    opacity: 0.5;
                    cursor: not-allowed;
                }

                .typing-indicator {
                    display: flex;
                    gap: 0.25rem;
                    padding: 0.75rem 1rem;
                }

                .typing-indicator span {
                    width: 6px;
                    height: 6px;
                    background: #818cf8;
                    border-radius: 50%;
                    animation: typing 1.4s infinite;
                }

                .typing-indicator span:nth-child(2) { animation-delay: 0.2s; }
                .typing-indicator span:nth-child(3) { animation-delay: 0.4s; }

                @keyframes typing {
                    0%, 60%, 100% { transform: translateY(0); opacity: 0.7; }
                    30% { transform: translateY(-8px); opacity: 1; }
                }

                @media (max-width: 480px) {
                    .chatbot-window {
                        width: calc(100vw - 40px);
                        height: calc(100vh - 100px);
                        right: 20px;
                    }
                }
            </style>
        `;

        document.head.insertAdjacentHTML('beforeend', styles);
        console.log('✅ Widget styles added to head');
    }

    init() {
        console.log('⚙️ Initializing widget event listeners...');
        const toggleBtn = document.getElementById('chatbot-toggle');
        const closeBtn = document.getElementById('chatbot-close');
        const sendBtn = document.getElementById('chatbot-send');
        const input = document.getElementById('chatbot-input');

        toggleBtn.addEventListener('click', () => this.toggleChat());
        closeBtn.addEventListener('click', () => this.closeChat());
        sendBtn.addEventListener('click', () => this.sendMessage());
        
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Quick action buttons
        document.querySelectorAll('.quick-action-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const message = btn.dataset.message;
                input.value = message;
                this.sendMessage();
            });
        });
    }

    toggleChat() {
        const window = document.getElementById('chatbot-window');
        const badge = document.getElementById('chatbot-badge');
        
        if (this.isOpen) {
            this.closeChat();
        } else {
            window.style.display = 'flex';
            this.isOpen = true;
            badge.style.display = 'none';
            document.getElementById('chatbot-input').focus();
        }
    }

    closeChat() {
        const window = document.getElementById('chatbot-window');
        window.style.display = 'none';
        this.isOpen = false;
    }

    async sendMessage() {
        const input = document.getElementById('chatbot-input');
        const message = input.value.trim();
        
        if (!message) return;

        // Add user message
        this.addMessage(message, 'user');
        input.value = '';

        // Show typing
        this.showTyping();

        try {
            const response = await fetch(`${this.apiBase}/api/chatbot/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('📥 Chatbot API response:', data);
            
            this.hideTyping();
            
            // Check if response exists
            if (data && data.response) {
                this.addMessage(data.response, 'bot');
            } else {
                console.error('Invalid response format:', data);
                this.addMessage("I received an invalid response. Please try again.", 'bot');
            }

        } catch (error) {
            console.error('💥 Chat error:', error);
            this.hideTyping();
            this.addMessage("Sorry, I'm having trouble connecting. Please check if the server is running.", 'bot');
        }
    }

    addMessage(text, sender) {
        const messagesDiv = document.getElementById('chatbot-messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';

        const parts = sender === 'bot' ? this.splitSources(text) : { body: String(text ?? ''), sources: [] };
        const p = document.createElement('p');
        p.innerHTML = this.formatMessage(parts.body);
        contentDiv.appendChild(p);

        if (sender === 'bot' && parts.sources.length > 0) {
            const sourcesDiv = document.createElement('div');
            sourcesDiv.className = 'message-sources';

            const title = document.createElement('div');
            title.className = 'sources-title';
            title.textContent = 'Sources';
            sourcesDiv.appendChild(title);

            const ul = document.createElement('ul');
            ul.className = 'sources-list';
            parts.sources.forEach((s) => {
                const li = document.createElement('li');
                li.textContent = s;
                ul.appendChild(li);
            });
            sourcesDiv.appendChild(ul);
            contentDiv.appendChild(sourcesDiv);
        }
        
        messageDiv.appendChild(contentDiv);
        messagesDiv.appendChild(messageDiv);
        
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
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

    showTyping() {
        const messagesDiv = document.getElementById('chatbot-messages');
        const typingDiv = document.createElement('div');
        typingDiv.id = 'typing-indicator';
        typingDiv.className = 'message bot-message';
        typingDiv.innerHTML = `
            <div class="message-content">
                <div class="typing-indicator">
                    <span></span><span></span><span></span>
                </div>
            </div>
        `;
        messagesDiv.appendChild(typingDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    hideTyping() {
        const typing = document.getElementById('typing-indicator');
        if (typing) typing.remove();
    }
}

// Initialize widget when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('🤖 Initializing WebShield Chatbot Widget...');
        new ChatbotWidget();
    });
} else {
    console.log('🤖 Initializing WebShield Chatbot Widget...');
    new ChatbotWidget();
}
