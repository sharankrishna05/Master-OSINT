# OSINT Arsenal & Nexus Intelligence Suite

Self-contained unified OSINT toolkit combining:
- **Investigation Hub**: Multi-source lookup engine (username / email / phone / domain / IP), website reconnaissance (30+ parallel checks), NetworkX threat graphs, and consensus scoring.
- **Nexus Account Sentinel**: Asynchronous email registration checks (GitHub, Twitter/X, Reddit, Spotify, Discord) and Have I Been Pwned (HIBP v3) breach intelligence with real-time SSE streaming.
- **OSINT-HUB (2,466 Tools)**: Bundled, auto-seeded SQLite catalog across 31 disciplines with target routing and HTML/JSON reporting.
- **DorkForge Suite**: Multi-engine Google dork template compiler.
- **A.R.I.A. AI Assistant**: Interactive conversational OSINT copilot with optional Gemini 1.5 integration.

## Quickstart (Local)

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Set ARSENAL_DEFAULT_KEYS in .env to a private, randomly generated API key.

# Run web UI + API (http://localhost:8080)
python -m osint_arsenal serve
```

## Deployment

### 1. Docker / Docker Compose (Recommended)

```bash
cp .env.example .env
# Edit .env and set ARSENAL_JWT_SECRET, ARSENAL_DEFAULT_KEYS, ARSENAL_ADMIN_EMAIL,
# ARSENAL_ADMIN_PASSWORD, and optional API keys
docker compose up -d --build
```

The service exposes port `8080` and includes a built-in `/health` liveness probe and persistent named volumes for SQLite databases (`/app/data`) and generated reports (`/app/reports`).

### 2. Render

The included `render.yaml` configures a free Docker web service. Free services
have an ephemeral filesystem and may spin down when idle, so SQLite databases,
accounts, and generated reports can be lost on restart or redeploy. This setup
is for demos, not persistent production use. Set the required
`ARSENAL_ADMIN_EMAIL` and `ARSENAL_ADMIN_PASSWORD` values in Render's Blueprint
setup; do not put credentials in the repository. Local account registration is
enabled for ordinary user accounts, while Google sign-in is disabled. New
registrations cannot grant themselves administrator privileges. Investigation
and report APIs require an authenticated account.

### 3. Other Cloud PaaS (Railway, Fly.io, Heroku)

The repository includes `Dockerfile`, `Procfile`, and `render.yaml`, and automatically binds to the platform-assigned `$PORT` environment variable.

Required / Recommended Environment Variables:
- `PORT` (provided automatically by PaaS; defaults to `8080`)
- `ARSENAL_JWT_SECRET` (strong random secret for JWT signing)
- `ARSENAL_ADMIN_EMAIL` & `ARSENAL_ADMIN_PASSWORD` (optional bootstrap admin login)
- `ARSENAL_DEFAULT_KEYS` (comma-separated API keys for `/api/lookup` and `/api/webcheck`)
- `HIBP_API_KEY` (optional Have I Been Pwned v3 API key)
- `GEMINI_API_KEY` (optional Google Gemini API key for A.R.I.A.)

## CLI & MCP Usage

```bash
python -m osint_arsenal modules
python -m osint_arsenal lookup alice --kind username
python -m osint_arsenal webcheck https://example.com -f html -o site.html
python -m osint_arsenal cti 8.8.8.8
python -m osint_arsenal mcp --transport stdio
```

## Testing

```bash
python -m pytest
```

## Legal Notice

For authorized security research and defensive intelligence only. Verify critical findings at the source.
