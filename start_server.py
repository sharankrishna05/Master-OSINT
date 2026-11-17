import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import uvicorn
from osint_arsenal.api.server import create_app
from osint_arsenal.config import settings

if __name__ == "__main__":
    app = create_app()
    print(f"OSINT Arsenal server starting on http://{settings.host}:{settings.port}")
    uvicorn.run(app, host=settings.host, port=settings.port)
