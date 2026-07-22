.\venv\Scripts\Activate.ps1 


cd backend   

python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000


Any terminal - cloudflared tunnel --url http://localhost:8000