import json
import sys
path = sys.argv[1]
with open(path) as f:
    data = json.load(f)
print('Total records:', len(data))
success = [d for d in data if d['error'] is None]
print('Successful predictions:', len(success))
failed = [d for d in data if d['error'] is not None]
print('Failed predictions:', len(failed))
if failed:
    print('First few errors:')
    for d in failed[:3]:
        print(f'  {d[\"record_id\"]}: {d[\"error\"]}')
