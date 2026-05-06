import asyncio
import sys
import uvicorn
from dotenv import load_dotenv

if __name__ == "__main__":
    # Load environment variables from .env file
    load_dotenv()
    
    if sys.platform == 'win32':
        # Force ProactorEventLoop on Windows
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    print("Starting VigilantLink Backend on http://localhost:8000")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
