import copy
import importlib.util
from pathlib import Path
import sys

root=Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('regression',root/'tools/check_regression.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
baseline={'schema_version':'0.1','seed':1,'compiler':'cc','packages':[], 'results':[{
    'project':'example','function':'f','status':'TESTED','attempted_cases':2,'cases_sha256':'abc','source_sha256':'def',
    'validation':{'passed':2,'mismatches':0,'return_comparison':'bits'}}]}
assert module.compare(baseline,copy.deepcopy(baseline))['status']=='PASS'
for field,value in [('status','BLOCKED'),('cases_sha256','other'),('source_sha256','other')]:
    changed=copy.deepcopy(baseline);changed['results'][0][field]=value
    assert module.compare(baseline,changed)['status']=='FAIL'
for field,value in [('passed',1),('mismatches',1),('return_comparison','sign')]:
    changed=copy.deepcopy(baseline);changed['results'][0]['validation'][field]=value
    assert module.compare(baseline,changed)['status']=='FAIL'
changed=copy.deepcopy(baseline);changed['results']=[]
assert module.compare(baseline,changed)['status']=='FAIL'
print('Baseline comparison: matching evidence accepted; 7 regression/incomparable conditions rejected')
