"""Пакет datapulse импортируется из src без установки:
единственный заявленный способ запуска — docker, pyproject нет."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
