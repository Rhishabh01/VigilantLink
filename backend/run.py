import asyncio
import os
import sys
import uvicorn
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    
    # Playwright requires ProactorEventLoop on Windows for subprocess support
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    port = int(os.getenv("PORT", 8000))
    print(f"Starting VigilantLink Backend on http://0.0.0.0:{port}")
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
