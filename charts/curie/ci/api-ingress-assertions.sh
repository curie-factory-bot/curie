#!/usr/bin/env bash
#
# Render-assertion test for the API ingress (issue #1238).
#
# The API is the one endpoint reached from outside the cluster: every
# authenticated call carries `X-API-Key` as a plain header, and GitHub posts
# webhooks to it. Without TLS both cross the network in the clear.
#
# The failure this guards against is not "TLS is missing" -- it is an Ingress
# that LOOKS configured and protects nothing. Seven assertions:
#
#   (a) Off by default. An ingress needs a controller, a hostname and a cert
#       source; none can be invented, so a default-on ingress would render an
#       object that silently does nothing.
#   (b) Enabling without a host FAILS the render, rather than producing a
#       host-less rule that matches every request reaching the controller.
#   (c) Enabled with a host renders a TLS block for that host.
#   (d) tls.enabled=false renders the rules WITHOUT a tls block -- for a
#       controller terminating TLS upstream. It must not silently keep tls.
#   (e) An empty secretName omits the field entirely. `secretName: ""` makes a
#       controller hunt for a Secret literally named "", which fails in a way
#       that looks like a missing certificate rather than a config error.
#   (f) The backend points at the api Service and its configured port, not a
#       hardcoded 8000 that drifts when api.service.port changes.
#   (g) Uvicorn receives the configured trusted proxy address so its client
#       address matches the ingress path used by console rate limiting.
#   (h) Wildcard and universal CIDR values fail rendering so callers cannot
#       spoof a new address to escape a console rate limit budget.
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL [$1] $2" >&2; exit 1; }
render() { helm template curie "$CHART" "$@" 2>&1; }

# (a) The default render must SUCCEED and contain no Ingress. Both halves
#     matter: counting Ingress objects in output that failed to render at all
#     reports zero and passes for the wrong reason -- which is exactly what
#     this assertion did before a falsification probe caught it.
if ! DEFAULT_OUT="$(helm template curie "$CHART" 2>&1)"; then
  fail a "the DEFAULT render failed; enabling the ingress must not be required
  $(head -3 <<<"$DEFAULT_OUT")"
fi
[ "$(grep -c '^kind: Ingress' <<<"$DEFAULT_OUT" || true)" -eq 0 ] \
  || fail a "an Ingress renders by default; it must be opt-in"

# (b)
if render --set api.ingress.enabled=true -s templates/api-ingress.yaml >/dev/null 2>&1; then
  fail b "enabling the ingress without a host succeeded; it must fail the render"
fi
# Captured rather than piped: helm exits non-zero here by design, and under
# `set -o pipefail` that would fail the pipeline even when grep matches.
MISSING_HOST="$(render --set api.ingress.enabled=true -s templates/api-ingress.yaml || true)"
grep -q "api.ingress.host is required" <<<"$MISSING_HOST" \
  || fail b "the missing-host failure does not name the value to set"

BASE=(--set api.ingress.enabled=true --set api.ingress.host=curie.example.com)

# (c)
OUT="$(render "${BASE[@]}" -s templates/api-ingress.yaml)"
python3 - "$OUT" <<'PY' || exit 1
import sys, yaml
d = [x for x in yaml.safe_load_all(sys.argv[1]) if x][0]
tls = d["spec"].get("tls")
if not tls or tls[0]["hosts"] != ["curie.example.com"]:
    print(f"FAIL [c] tls block wrong: {tls}", file=sys.stderr); sys.exit(1)
PY

# (d)
OUT="$(render "${BASE[@]}" --set api.ingress.tls.enabled=false -s templates/api-ingress.yaml)"
python3 - "$OUT" <<'PY' || exit 1
import sys, yaml
d = [x for x in yaml.safe_load_all(sys.argv[1]) if x][0]
if "tls" in d["spec"]:
    print("FAIL [d] tls.enabled=false still rendered a tls block", file=sys.stderr); sys.exit(1)
if not d["spec"].get("rules"):
    print("FAIL [d] rules disappeared with tls disabled", file=sys.stderr); sys.exit(1)
PY

# (e)
OUT="$(render "${BASE[@]}" -s templates/api-ingress.yaml)"
grep -q 'secretName: ""' <<<"$OUT" \
  && fail e 'an empty secretName rendered as secretName: "" -- omit the field instead'
OUT="$(render "${BASE[@]}" --set api.ingress.tls.secretName=my-cert -s templates/api-ingress.yaml)"
grep -q 'secretName: "my-cert"' <<<"$OUT" || fail e "a supplied secretName was not rendered"

# (f)
OUT="$(render "${BASE[@]}" --set api.service.port=9999 -s templates/api-ingress.yaml)"
python3 - "$OUT" <<'PY' || exit 1
import sys, yaml
d = [x for x in yaml.safe_load_all(sys.argv[1]) if x][0]
b = d["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]
if b["port"]["number"] != 9999:
    print(f"FAIL [f] backend port {b['port']['number']} ignores api.service.port", file=sys.stderr)
    sys.exit(1)
if not b["name"].endswith("-api"):
    print(f"FAIL [f] backend service {b['name']} is not the api service", file=sys.stderr)
    sys.exit(1)
PY

# (g) Check the API container environment, not an unrelated workload or a
# similarly named value elsewhere in the rendered chart.
for pair in '127.0.0.1 127.0.0.1' '192.0.2.10/32 192.0.2.10/32'; do
  read -r configured expected <<<"$pair"
  if [[ "$configured" == '127.0.0.1' ]]; then
    OUT="$(render -s templates/api.yaml)"
  else
    OUT="$(render --set-string "api.forwardedAllowIps=$configured" -s templates/api.yaml)"
  fi
  python3 - "$OUT" "$expected" <<'PY' || exit 1
import sys

import yaml

deployments = [
    document for document in yaml.safe_load_all(sys.argv[1])
    if document and document.get("kind") == "Deployment"
]
if len(deployments) != 1:
    raise SystemExit(f"FAIL [g] expected one API Deployment, found {len(deployments)}")
containers = deployments[0]["spec"]["template"]["spec"]["containers"]
api = [container for container in containers if container["name"] == "api"]
if len(api) != 1:
    raise SystemExit(f"FAIL [g] expected one API container, found {len(api)}")
values = [
    entry.get("value") for entry in api[0]["env"]
    if entry["name"] == "FORWARDED_ALLOW_IPS"
]
if values != [sys.argv[2]]:
    raise SystemExit(f"FAIL [g] FORWARDED_ALLOW_IPS rendered {values!r}, expected {[sys.argv[2]]!r}")
PY
done

# (h) Reject each unsafe entry even when combined with a valid proxy address.
for unsafe in '*' '0.0.0.0/0' '::/0'; do
  if OUT="$(helm template curie "$CHART" --set-string "api.forwardedAllowIps=192.0.2.10/32\,$unsafe" -s templates/api.yaml 2>&1)"; then
    fail h "api.forwardedAllowIps accepted $unsafe"
  fi
  grep -q 'api.forwardedAllowIps must name exact trusted proxy IPs or narrow CIDRs' <<<"$OUT" \
    || fail h "the rejection of $unsafe did not name the required setting"
done

echo "api-ingress-assertions: all eight assertions passed"
