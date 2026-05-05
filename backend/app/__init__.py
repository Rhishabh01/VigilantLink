import asyncio
import sys

# Ensure the ProactorEventLoop is used on Windows for Playwright/Subprocess support
# This needs to happen as early as possible.
if sys.platform == 'win32':
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except AttributeError:
        pass
