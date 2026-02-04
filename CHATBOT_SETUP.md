# AI Chatbot Setup

The chatbot now uses **real AI** powered by OpenAI's GPT models to analyze your packet captures intelligently.

## 🚀 Quick Setup

### 1. Get an OpenAI API Key

1. Go to [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. Sign up or log in
3. Click "Create new secret key"
4. Copy your API key (starts with `sk-...`)

### 2. Configure the Backend

Create a `.env` file in the `backend/` directory:

```bash
cd backend
copy .env.example .env
```

Edit `.env` and add your API key:

```
OPENAI_API_KEY=sk-your-actual-api-key-here
```

### 3. Restart the Backend

Stop the backend (Ctrl+C) and restart:

```bash
python main.py
```

## ✨ What the AI Chatbot Can Do

- **Analyze packet captures** contextually based on your uploaded file
- **Answer questions** about IPs, protocols, threats, patterns
- **Explain security issues** in simple terms
- **Search for specific data** (IPs, ports, protocols)
- **Provide recommendations** based on the analysis
- **Natural conversation** - ask follow-up questions!

## 💡 Example Questions

- "What are the biggest security concerns in this capture?"
- "Is there any suspicious traffic from 192.168.1.100?"
- "What protocols are being used most?"
- "Explain the DNS queries in simple terms"
- "Are there any port scans happening?"
- "What IPs should I be worried about?"

## 🔒 Fallback Mode

If you don't set up an API key, the chatbot will still work in limited mode with basic responses. But for the best experience, set up your OpenAI API key!

## 💰 Costs

The chatbot uses `gpt-4o-mini` which is very cost-effective:
- ~$0.15 per 1M input tokens
- ~$0.60 per 1M output tokens
- A typical conversation costs less than $0.01

## 🛡️ Security

- Your API key is stored locally in the `.env` file
- Never commit `.env` to git (already in `.gitignore`)
- The API key is only used to communicate with OpenAI
- Your packet data is sent to OpenAI for analysis (check their privacy policy if concerned)
