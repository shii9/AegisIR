#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
TEMP="$(mktemp -d)";trap 'rm -rf "$TEMP"' EXIT
export AEGISIR_HOME="$TEMP/store"
BIN="${BIN:-./dist/aegisir}"
"$BIN" doctor > "$TEMP/doctor.json"
"$BIN" demo > "$TEMP/demo.json"
CASE="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["case_id"])' "$TEMP/demo.json")"
"$BIN" findings "$CASE" > "$TEMP/findings.json"
"$BIN" verify "$CASE" > "$TEMP/verify.json"
"$BIN" report "$CASE" --output "$TEMP/report.md" > "$TEMP/export.json"
"$BIN" checklist "$CASE" > "$TEMP/checklist.json"
"$BIN" show "$CASE" > "$TEMP/case.json"
python3 - "$TEMP" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);fs=json.loads((p/'findings.json').read_text())
assert len(fs)>=4
assert json.loads((p/'verify.json').read_text())['integrity_ok']
assert (p/'report.md').is_file()
assert 'Synthetic' in (p/'report.md').read_text()
print('End-to-end demo: cases, findings, integrity, checklist, report PASS')
PY
# Real-machine read-only collector smoke; avoids collecting logs/PII into artifacts.
"$BIN" new --title 'Collector smoke' --asset 'local-test' --analyst 'ci' --severity low > "$TEMP/local.json"
LOCAL="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["case_id"])' "$TEMP/local.json")"
"$BIN" scan "$LOCAL" --module users > "$TEMP/userscan.json"
"$BIN" verify "$LOCAL" > "$TEMP/localverify.json"
python3 - "$TEMP" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);r=json.loads((p/'userscan.json').read_text());assert r['modules'][0]['module']=='users'
assert json.loads((p/'localverify.json').read_text())['integrity_ok']
print('Live Linux read-only user collection PASS')
PY
"$BIN" scan "$LOCAL" --module all > "$TEMP/allscan.json"
"$BIN" verify "$LOCAL" > "$TEMP/allverify.json"
python3 - "$TEMP" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);r=json.loads((p/'allscan.json').read_text())
assert len(r['modules'])==12, r
assert all(x['status'] in ('ok','partial','unavailable') for x in r['modules'])
assert json.loads((p/'allverify.json').read_text())['integrity_ok']
print('All 12 Linux read-only collectors PASS (partial permission warnings allowed)')
PY
