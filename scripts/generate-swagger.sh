#!/usr/bin/env bash
# Single source of truth for swagger spec generation.
# Used by: go:generate (main.go), CI pipeline (swagger job), and local development.
#
# Usage: ./scripts/generate-swagger.sh [--check]
#   --check   Fail if generated output differs from committed docs/ (CI mode).

set -euo pipefail

SWAG_VERSION="v1.16.6"
SWAG_BIN="$(go env GOPATH)/bin/swag-${SWAG_VERSION}"

# Install the pinned version if not already present.
if [[ ! -x "${SWAG_BIN}" ]]; then
  echo "Installing swag ${SWAG_VERSION}..."
  GOBIN="$(go env GOPATH)/bin" go install "github.com/swaggo/swag/cmd/swag@${SWAG_VERSION}"
  mv "$(go env GOPATH)/bin/swag" "${SWAG_BIN}"
fi

"${SWAG_BIN}" init \
  --parseDependency \
  --parseDepth 3 \
  --output docs/ \
  --generalInfo main.go

# Normalize swag output: remove non-deterministic time.Duration constants
# that swag includes depending on the build environment and Go stdlib version.
# swag includes a non-deterministic subset of: Nanosecond, Microsecond,
# Millisecond, Second, Minute, Hour, minDuration, maxDuration.
# We keep only Nanosecond/Microsecond/Millisecond and strip the rest.
#
# For docs/swagger.json: parse as JSON, normalise, re-serialise (avoids
# trailing-comma issues that arise from line-oriented sed deletions).
# For docs/docs.go: use targeted sed on the known lines; the file is a Go
# source with template placeholders so it cannot be round-tripped through
# json.load.  After removing lines we also repair any trailing commas left
# on the new last element of each affected array.
# For docs/swagger.yaml: line-based deletion is safe; YAML has no trailing
# commas.

python3 - <<'PYEOF'
import json

KEEP_VARNAMES = {"Nanosecond", "Microsecond", "Millisecond"}
REMOVE_VARNAMES = {"minDuration", "maxDuration", "Second", "Minute", "Hour"}

def normalize(schema):
    enums    = schema.get("enum", [])
    varnames = schema.get("x-enum-varnames", [])
    if not enums:
        return schema
    if len(varnames) != len(enums):
        return schema
    pairs = list(zip(enums, varnames))
    kept = [(e, v) for e, v in pairs if v not in REMOVE_VARNAMES]
    if not kept:
        return schema
    seen = set()
    deduped = []
    for e, v in kept:
        key = (e, v)
        if key not in seen:
            seen.add(key)
            deduped.append(key)
    new_e, new_v = zip(*deduped)
    schema = dict(schema)
    schema["enum"] = list(new_e)
    schema["x-enum-varnames"] = list(new_v)
    return schema

with open("docs/swagger.json", "rb") as f:
    raw = f.read()
had_trailing_newline = raw.endswith(b"\n")

spec = json.loads(raw)
for key in list(spec.get("definitions", {})):
    spec["definitions"][key] = normalize(spec["definitions"][key])

serialised = json.dumps(spec, indent=4, ensure_ascii=False)
if had_trailing_newline:
    serialised += "\n"
with open("docs/swagger.json", "w") as f:
    f.write(serialised)
print("docs/swagger.json normalised")
PYEOF

# Normalise all swagger outputs: remove non-deterministic time.Duration
# constants and deduplicate entries that swag discovers from multiple sources.
# We keep only Nanosecond/Microsecond/Millisecond and strip the rest.
#
# docs.go contains Go template syntax so cannot be parsed as JSON.
# swagger.yaml may not have PyYAML available, so all three files are
# processed with targeted regex + line-based logic inside a single Python
# script.

python3 - <<'PYEOF'
import json
import re

KEEP_VARNAMES = {"Nanosecond", "Microsecond", "Millisecond"}
REMOVE_VARNAMES = {"minDuration", "maxDuration", "Second", "Minute", "Hour"}

# --- helpers ---

def dedup_pairs(pairs):
    seen = set()
    out = []
    for e, v in pairs:
        key = (e, v)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out

def normalize_pairs(pairs):
    kept = [(e, v) for e, v in pairs if v not in REMOVE_VARNAMES]
    return dedup_pairs(kept)

# --- swagger.json (full JSON parse) ---

with open("docs/swagger.json", "rb") as f:
    raw = f.read()
had_trailing_newline = raw.endswith(b"\n")

spec = json.loads(raw)
for key in list(spec.get("definitions", {})):
    schema = spec["definitions"][key]
    enums    = schema.get("enum", [])
    varnames = schema.get("x-enum-varnames", [])
    if not enums or len(varnames) != len(enums):
        continue
    pairs = list(zip(enums, varnames))
    kept = normalize_pairs(pairs)
    if not kept:
        continue
    new_e, new_v = zip(*kept)
    schema = dict(schema)
    schema["enum"] = list(new_e)
    schema["x-enum-varnames"] = list(new_v)

serialised = json.dumps(spec, indent=4, ensure_ascii=False)
if had_trailing_newline:
    serialised += "\n"
with open("docs/swagger.json", "w") as f:
    f.write(serialised)
print("docs/swagger.json normalised")

# --- docs.go (Go source with backtick template — regex-based) ---

with open("docs/docs.go") as f:
    text = f.read()

start = text.index("const docTemplate = `") + len("const docTemplate = `")
end   = text.index("`", start)
template = text[start:end]

# Remove unwanted time.Duration enum values and varnames.
for pattern in [
    r'-?9223372036854775808,?\n',
    r' 9223372036854775807,?\n',
    r' 1000000000,?\n',
    r' 60000000000,?\n',
    r' 3600000000000,?\n',
    r'"minDuration",?\n',
    r'"maxDuration",?\n',
    r'"Second",?\n',
    r'"Minute",?\n',
    r'"Hour",?\n',
]:
    template = re.sub(pattern, '', template)

# Deduplicate entries inside time.Duration enum and x-enum-varnames arrays.
def dedup_duration_section(template):
    # Match the entire time.Duration definition block.
    dur_re = re.compile(r'("time\.Duration":\s*\{[^}]*\})', re.DOTALL)
    def replace_dur(m):
        block = m.group(1)
        for array_key in ['"enum"', '"x-enum-varnames"']:
            arr_re = re.compile(
                r'(' + re.escape(array_key) + r':\s*\[)([^\]]*)(\])',
                re.DOTALL
            )
            def dedup_arr(m2):
                items = [line.strip().rstrip(',').strip('"')
                         for line in m2.group(2).split('\n')
                         if line.strip()]
                items = [item for item in items if item]
                seen = set()
                deduped = []
                for item in items:
                    if item not in seen:
                        seen.add(item)
                        deduped.append(item)
                # Reconstruct with proper indentation and commas
                lines = []
                for item in deduped:
                    if array_key == '"enum"':
                        lines.append('                ' + item + ',')
                    else:
                        lines.append('                "' + item + '",')
                return m2.group(1) + '\n' + '\n'.join(lines) + '\n            ' + m2.group(3)
            block = arr_re.sub(dedup_arr, block)
        return block
    return dur_re.sub(replace_dur, template)

template = dedup_duration_section(template)

# Remove trailing commas from last array elements.
template = re.sub(r',(\s*\n\s*[\]\}])', r'\1', template)

text = text[:start] + template + text[end:]
with open("docs/docs.go", "w") as f:
    f.write(text)
print("docs/docs.go normalised")

# --- swagger.yaml (line-based — no PyYAML dependency) ---

with open("docs/swagger.yaml") as f:
    lines = f.readlines()

REMOVE_YAML_PATTERNS = {
    '- -9223372036854775808', '- 9223372036854775807',
    '- minDuration', '- maxDuration',
    '- 1000000000', '- 60000000000', '- 3600000000000',
    '- Second', '- Minute', '- Hour',
}

result = []
in_duration = False
in_enum = False
in_varnames = False
seen_enum = set()
seen_varn = set()

for line in lines:
    if line.startswith('  time.Duration:'):
        in_duration = True
        result.append(line)
        continue
    if in_duration and line.startswith('  ') and not line.startswith('    '):
        in_duration = False
        in_enum = False
        in_varnames = False
        seen_enum.clear()
        seen_varn.clear()
        result.append(line)
        continue
    if in_duration:
        stripped = line.strip()
        if stripped == 'enum:':
            in_enum = True
            in_varnames = False
            seen_enum.clear()
            result.append(line)
            continue
        if stripped == 'x-enum-varnames:':
            in_enum = False
            in_varnames = True
            seen_varn.clear()
            result.append(line)
            continue
        if in_enum:
            if stripped in REMOVE_YAML_PATTERNS:
                continue
            if stripped in seen_enum:
                continue
            seen_enum.add(stripped)
            result.append(line)
            continue
        if in_varnames:
            if stripped in REMOVE_YAML_PATTERNS:
                continue
            if stripped in seen_varn:
                continue
            seen_varn.add(stripped)
            result.append(line)
            continue
    result.append(line)

with open("docs/swagger.yaml", "w") as f:
    f.writelines(result)
print("docs/swagger.yaml normalised")
PYEOF

if [[ "${1:-}" == "--check" ]]; then
  if ! git diff --exit-code docs/; then
    echo ""
    echo "swagger spec is out of date. Run the following command and commit the result:"
    echo "  ./scripts/generate-swagger.sh"
    exit 1
  fi
fi
