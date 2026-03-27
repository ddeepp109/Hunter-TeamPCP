#!/usr/bin/env bash
# Deploy PyPI ↔ GitHub Monitor to Fly.io
# Usage: ./deploy.sh
set -euo pipefail

APP_NAME="pypi-github-monitor"
REGION="sjc"
VOLUME_NAME="monitor_data"

echo "═══════════════════════════════════════════════"
echo "  PyPI ↔ GitHub Monitor – Fly.io Deployment"
echo "═══════════════════════════════════════════════"

# 1. Check flyctl is installed
if ! command -v flyctl &>/dev/null; then
    echo "❌ flyctl not found. Install: curl -L https://fly.io/install.sh | sh"
    exit 1
fi

# 2. Check auth
if ! flyctl auth whoami &>/dev/null; then
    echo "→ Not logged in. Running 'flyctl auth login'..."
    flyctl auth login
fi

# 3. Launch or check existing app
if flyctl apps list 2>/dev/null | grep -q "$APP_NAME"; then
    echo "✓ App '$APP_NAME' already exists"
else
    echo "→ Creating app '$APP_NAME'..."
    flyctl apps create "$APP_NAME" --machines
fi

# 4. Create volume if it doesn't exist
if flyctl volumes list -a "$APP_NAME" 2>/dev/null | grep -q "$VOLUME_NAME"; then
    echo "✓ Volume '$VOLUME_NAME' already exists"
else
    echo "→ Creating 1GB persistent volume..."
    flyctl volumes create "$VOLUME_NAME" \
        --app "$APP_NAME" \
        --region "$REGION" \
        --size 1 \
        --yes
fi

# 5. Set GitHub token secret
if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo ""
    echo "⚠  GITHUB_TOKEN not set in environment."
    echo "   Set it with: flyctl secrets set GITHUB_TOKEN=ghp_xxx -a $APP_NAME"
    echo ""
else
    echo "→ Setting GITHUB_TOKEN secret..."
    echo "$GITHUB_TOKEN" | flyctl secrets set GITHUB_TOKEN="$GITHUB_TOKEN" -a "$APP_NAME"
fi

# 6. Deploy
echo "→ Deploying to Fly.io..."
flyctl deploy --app "$APP_NAME" --remote-only

# 7. Show status
echo ""
echo "═══════════════════════════════════════════════"
flyctl status -a "$APP_NAME"
echo ""
echo "✅ Deployed! Open: https://${APP_NAME}.fly.dev"
echo "═══════════════════════════════════════════════"
