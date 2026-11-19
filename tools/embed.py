"""Embed a build-generated, trusted fixture; no external downloads."""
from pathlib import Path
import sys
data=Path(sys.argv[1]).read_bytes()
Path(sys.argv[2]).write_text('#pragma once\ninline constexpr unsigned char zvril_demo_bytes[]={'+','.join(map(str,data))+'};\n')
