#!/usr/bin/env python3
"""便捷入口脚本"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from malware_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
