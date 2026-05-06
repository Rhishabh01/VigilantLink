import asyncio
import sys
import uvicorn
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    
    # Playwright requires ProactorEventLoop on Windows for subprocess support
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    print("Starting VigilantLink Backend on http://localhost:8000")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
