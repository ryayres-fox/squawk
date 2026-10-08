#!/usr/bin/env bash
# One-file distribution of the app: a zipapp of the squawk/ package.
# The installer (install-tools.sh) stays with the checkout; the zipapp is the app.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
STAGE=$(mktemp -d)
mkdir -p "$STAGE/app" "$HERE/dist"
cp -R "$HERE/squawk" "$STAGE/app/"
# The toolbench installer travels INSIDE the package. A zipapp has no "beside",
# and `--install` answered "install-tools.sh not found beside squawk.py" on the
# one machine the zipapp exists for -- which is also the machine with no
# scanners on it. `installer_script()` reads it back out with pkgutil, which
# works the same for a directory package and for one inside a zip.
cp "$HERE/install-tools.sh" "$STAGE/app/squawk/"
find "$STAGE/app" -name __pycache__ -type d -prune -exec rm -rf {} +

# Our own entry point, not zipapp's `-m` one. The generated form is
#     import squawk.cli
#     squawk.cli.main()
# which calls main and THROWS THE RETURN VALUE AWAY, so the process always
# exits 0. Every refusal the tool makes -- a public DAST target, a cloud query
# without its acknowledgement, a profile carrying a destructive option -- came
# back rc=0 from the zipapp while the same command from the checkout gave
# rc=2. A refusal that looks like a success is the one thing this tool exists
# not to do, and the zipapp did it for its whole life until 2026-09-08.
cat > "$STAGE/app/__main__.py" <<'ENTRY'
import sys

from squawk.cli import main

sys.exit(main())
ENTRY
python3 -m zipapp "$STAGE/app" -o "$HERE/dist/squawk.pyz" -p "/usr/bin/env python3"
rm -rf "$STAGE"
echo "built $HERE/dist/squawk.pyz"
python3 "$HERE/dist/squawk.pyz" --version
