"""
Aiohttp web server for the live dashboard.
Serves the dashboard at http://0.0.0.0:8000
Provides SSE endpoint for real-time updates and REST API for state.
"""
import asyncio
import json
import time
import threading
from pathlib import Path
from typing import Any

from aiohttp import web

from userhunt.web.store import store

TEMPLATES_DIR = Path(__file__).parent / "templates"


async def index_handler(request: web.Request) -> web.Response:
    """Serve the main dashboard HTML."""
    html_path = TEMPLATES_DIR / "index.html"
    if html_path.exists():
        html = html_path.read_text()
        return web.Response(text=html, content_type="text/html")
    return web.Response(text="<h1>Dashboard template not found</h1>", status=404)


async def api_state(request: web.Request) -> web.Response:
    """Return full state snapshot as JSON."""
    since = float(request.query.get("since", "0"))
    snapshot = store.snapshot(since=since)
    return web.json_response(snapshot)


async def api_log(request: web.Request) -> web.Response:
    """Add a log entry via POST."""
    try:
        data = await request.json()
        store.log(
            message=data.get("message", ""),
            level=data.get("level", "info"),
            source=data.get("source", "api"),
        )
        return web.json_response({"ok": True})
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)


async def sse_handler(request: web.Request) -> web.StreamResponse:
    """
    Server-Sent Events endpoint.
    Pushes state updates to the browser every 1 second.
    """
    response = web.StreamResponse(
        status=200,
        reason="OK",
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
    await response.prepare(request)

    last_push = 0.0
    try:
        while True:
            now = time.time()
            if now - last_push >= 1.0:
                snapshot = store.snapshot(since=last_push if last_push > 0 else 0)
                payload = json.dumps(snapshot, default=str)
                await response.write(f"data: {payload}\n\n".encode())
                last_push = now
            await asyncio.sleep(0.5)
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        pass
    finally:
        try:
            await response.write_eof()
        except Exception:
            pass

    return response


def create_app() -> web.Application:
    """Create and configure the aiohttp app."""
    app = web.Application()

    app.router.add_get("/", index_handler)
    app.router.add_get("/api/state", api_state)
    app.router.add_post("/api/log", api_log)
    app.router.add_get("/sse", sse_handler)

    return app


def start_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Start the web dashboard server (blocking)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app = create_app()
    runner = web.AppRunner(app)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, host, port)
    loop.run_until_complete(site.start())
    try:
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        loop.run_until_complete(runner.cleanup())
        loop.close()


def start_server_thread(host: str = "0.0.0.0", port: int = 8000) -> threading.Thread:
    """Start the web dashboard in a background thread."""
    t = threading.Thread(target=start_server, args=(host, port), daemon=True)
    t.start()
    return t
