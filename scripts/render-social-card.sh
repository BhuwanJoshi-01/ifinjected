#!/bin/sh
# Renders scripts/social-card/card.html to site/assets/social-card.png (1280x640), the image
# link previews and the repository's social preview use. Needs Google Chrome or Chromium.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
chrome=${CHROME:-$(command -v google-chrome || command -v chromium || command -v chromium-browser)}
"$chrome" --headless=new --disable-gpu --hide-scrollbars --allow-file-access-from-files \
    --force-device-scale-factor=1 --window-size=1280,640 --virtual-time-budget=3000 \
    --screenshot="$root/site/assets/social-card.png" "file://$root/scripts/social-card/card.html" 2>/dev/null
echo "wrote site/assets/social-card.png"
