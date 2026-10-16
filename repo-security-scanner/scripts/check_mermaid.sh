#!/usr/bin/env bash
# Render every ```mermaid block in the Markdown docs with the real Mermaid CLI (mmdc).
# Optional: needs Node.js, @mermaid-js/mermaid-cli and a Chromium. Not part of `pytest`.
#
#   npm install --prefix /tmp/mmd @mermaid-js/mermaid-cli@11.4.2   # with PUPPETEER_SKIP_DOWNLOAD=1
#   MMDC=/tmp/mmd/node_modules/.bin/mmdc CHROME=/path/to/chrome scripts/check_mermaid.sh
set -eu
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MMDC="${MMDC:-mmdc}"
CHROME="${CHROME:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 - "$ROOT" "$WORK" <<'PY'
import pathlib, re, sys
root, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
count = 0
for md in sorted([root / "README.md", *root.glob("docs/*.md")]):
    for i, block in enumerate(re.findall(r"```mermaid\n(.*?)```", md.read_text(encoding="utf-8"), re.S)):
        (out / f"{md.stem}-{i}.mmd").write_text(block, encoding="utf-8")
        count += 1
print(f"{count} diagram(s) extracted")
PY
if [ -n "$CHROME" ]; then
  printf '{"executablePath": "%s", "args": ["--no-sandbox", "--disable-gpu"]}' "$CHROME" > "$WORK/pptr.json"
  PPTR=(-p "$WORK/pptr.json")
else
  PPTR=()
fi
status=0
for f in "$WORK"/*.mmd; do
  if "$MMDC" "${PPTR[@]}" -q -i "$f" -o "${f%.mmd}.svg" >/dev/null 2>"$WORK/err.txt"; then
    echo "OK    $(basename "$f")"
  else
    echo "FAIL  $(basename "$f")"; sed 's/^/      /' "$WORK/err.txt" | head -5; status=1
  fi
done
exit "$status"
