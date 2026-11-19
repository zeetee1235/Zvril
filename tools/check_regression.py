"""Compare manifests from the same pinned, deterministic corpus and inputs."""
import argparse
import json
from pathlib import Path

def compare(baseline,current):
    errors=[]
    for field in ('schema_version','seed','compiler','packages'):
        if baseline.get(field)!=current.get(field):errors.append({'code':'INCOMPARABLE_MANIFEST','field':field})
    old={(r['project'],r['function']):r for r in baseline['results']}
    new={(r['project'],r['function']):r for r in current['results']}
    for key,previous in old.items():
        present=new.get(key)
        if present is None:errors.append({'code':'MISSING_TARGET','target':key});continue
        for field in ('attempted_cases','cases_sha256','source_sha256'):
            if previous.get(field)!=present.get(field):errors.append({'code':'INCOMPARABLE_INPUT','target':key,'field':field})
        if previous['status']=='TESTED' and present['status']!='TESTED':errors.append({'code':'SUPPORT_REGRESSION','target':key,'status':present['status']})
        p,n=previous.get('validation',{}),present.get('validation',{})
        if n.get('passed',0)<p.get('passed',0):errors.append({'code':'PASS_COUNT_REGRESSION','target':key})
        if n.get('mismatches',0)>p.get('mismatches',0):errors.append({'code':'MISMATCH_REGRESSION','target':key})
        if n.get('return_comparison')!=p.get('return_comparison'):errors.append({'code':'INCOMPARABLE_CONTRACT','target':key})
    return {'schema_version':'0.1','compared_targets':len(old),'status':'FAIL' if errors else 'PASS','diagnostics':errors}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('baseline',type=Path);p.add_argument('current',type=Path);p.add_argument('--out',type=Path);args=p.parse_args()
    report=compare(json.loads(args.baseline.read_text()),json.loads(args.current.read_text()))
    text=json.dumps(report,indent=2)+'\n'
    if args.out:args.out.write_text(text)
    print(text,end='');raise SystemExit(report['status']!='PASS')
