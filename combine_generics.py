import json
import glob
import os

folder = 'all_rules'
files = glob.glob(os.path.join(folder, 'rule_generic_*.json'))
combined = []

for f in files:
    if f.endswith('combined.json'):
        continue
    with open(f, 'r') as fp:
        try:
            data = json.load(fp)
            if isinstance(data, list):
                combined.extend(data)
            else:
                combined.append(data)
        except Exception as e:
            print(f"Error loading {f}: {e}")

with open(os.path.join(folder, 'rule_generics_combined.json'), 'w') as fp:
    json.dump(combined, fp, indent=2, ensure_ascii=False)

for f in files:
    if f.endswith('combined.json'):
        continue
    os.remove(f)

print(f"Combined {len(files)} files into rule_generics_combined.json and deleted the originals.")
