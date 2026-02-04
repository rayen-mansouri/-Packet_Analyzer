# Deployment Guide

This guide will help you deploy PacketAnalyzer to Vercel (frontend) and Render (backend).

## Prerequisites

- GitHub account
- Vercel account (free tier available)
- Render account (free tier available)
- Groq API key (free at https://console.groq.com)

## Step 1: Deploy Backend to Render

1. **Go to [Render](https://render.com)** and sign in
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository: `rayen-mansouri/-Packet_Analyzer`
4. Configure the service:
   - **Name**: `packetanalyzer-api`
   - **Root Directory**: `backend`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. **Add Environment Variables**:
   - Click "Environment" tab
   - Add: `GROQ_API_KEY` = `your_actual_groq_api_key`
   - Add: `GROQ_MODEL` = `llama-3.3-70b-versatile`
6. Click **"Create Web Service"**
7. **Copy your backend URL** (e.g., `https://packetanalyzer-api.onrender.com`)

## Step 2: Deploy Frontend to Vercel

1. **Go to [Vercel](https://vercel.com)** and sign in
2. Click **"Add New..."** → **"Project"**
3. Import your GitHub repository: `rayen-mansouri/-Packet_Analyzer`
4. Configure the project:
   - **Framework Preset**: Vite
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. **Add Environment Variables**:
   - Click "Environment Variables"
   - Add: `VITE_API_URL` = `https://packetanalyzer-api.onrender.com` (your Render backend URL)
6. Click **"Deploy"**
7. **Your app is live!** Vercel will give you a URL like `https://packet-analyzer.vercel.app`

## Step 3: Update CORS in Backend

After deployment, you need to update the CORS settings in your backend to allow requests from your Vercel domain.

1. Go to your Render dashboard
2. Navigate to your `packetanalyzer-api` service
3. Add an environment variable:
   - `ALLOWED_ORIGINS` = `https://your-vercel-app.vercel.app`
4. Redeploy the service

## Local Development

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
# Create .env file with OPENAI_API_KEY
python main.py
```

### Frontend
```bash
cd frontend
npm install
# Create .env file with VITE_API_URL=http://localhost:8000
npm run dev
```

## Environment Variables Summary

### Backend (.env)
- `GROQ_API_KEY` - Your Groq API key (get from https://console.groq.com)
- `GROQ_MODEL` - Model to use (default: `llama-3.3-70b-versatile`)

### Frontend (.env)
- `VITE_API_URL` - Backend API URL (local: `http://localhost:8000`, production: your Render URL)

## Troubleshooting

### Chatbot not working
- Verify `GROQ_API_KEY` is set in Render environment variables
- Check backend logs in Render dashboard

### CORS errors
- Ensure frontend URL is added to CORS allowed origins in backend
- Check `main.py` CORS configuration

### API connection failed
- Verify `VITE_API_URL` environment variable in Vercel
- Ensure backend is running on Render

## Free Tier Limitations

**Render Free Tier**:
- Service spins down after 15 minutes of inactivity
- First request after spin-down takes ~30 seconds
- 750 hours/month free

**Vercel Free Tier**:
- 100 GB bandwidth/month
- Unlimited deployments
- Custom domains supported

## Alternative: Railway (Backend)

If you prefer Railway over Render:

1. Go to [Railway](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your repository
4. Set root directory to `backend`
5. Add environment variable: `OPENAI_API_KEY`
6. Railway will auto-detect Python and deploy
7. Copy the generated URL and use it as `VITE_API_URL` in Vercel

## Need Help?

- Vercel Documentation: https://vercel.com/docs
- Render Documentation: https://render.com/docs
- Railway Documentation: https://docs.railway.app
