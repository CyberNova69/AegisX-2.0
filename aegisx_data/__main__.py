"""Allow running aegisx_data as a module: python -m aegisx_data"""

from aegisx_data.cli.main import main
import sys

sys.exit(main())
