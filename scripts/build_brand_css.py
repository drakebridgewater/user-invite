"""Build app/static/bridgewater.css from the design system's tokens.json and components/bundle.css.

Usage: python scripts/build_brand_css.py tokens.json bundle.css app/static/bridgewater.css
"""
import json, re, sys

tokens_path, bundle_path, out_path = sys.argv[1:4]
t = json.load(open(tokens_path))
bundle = open(bundle_path).read()

def val(v):
    m = re.fullmatch(r"\{(.+)\}", v)
    return f"var(--{m[1]})" if m else v

light, dark = [], []
for tok in t["color"]["tokens"]:
    v = tok["value"]
    if isinstance(v, str):
        light.append(f"--{tok['name']}:{val(v)}")
    else:
        light.append(f"--{tok['name']}:{val(v['light'])}")
        if v.get("dark") and v["dark"] != v["light"]:
            dark.append(f"--{tok['name']}:{val(v['dark'])}")
for fam, stack in t["type"]["families"].items():
    light.append(f"--font-{fam}:{stack}")
for fam in ("spacing", "radius", "stroke", "size"):
    for tok in t[fam]["tokens"]:
        light.append(f"--{tok['name']}:{tok['value']}")

dark_css = ";".join(dark)
css = [
    "/* bridgewater.digital design system: tokens.json + components/bundle.css.",
    "   Generated; edit the design system and rebuild rather than this file. */",
    ":root{" + ";".join(light) + ";color-scheme:light}",
    '@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){' + dark_css + ";color-scheme:dark}}",
    ':root[data-theme="dark"]{' + dark_css + ";color-scheme:dark}",
    re.sub(r'^@import[^;]+;\s*', "", bundle, flags=re.M).strip(),
]
open(out_path, "w").write("\n".join(css) + "\n")
print(f"wrote {out_path}: {len(light)} tokens, {len(dark)} dark overrides")
