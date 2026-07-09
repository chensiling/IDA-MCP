"""IDA 原子操作层（包）。

对外接口与拆分前的单文件 ida_api.py 完全一致：导入本包即可访问全部原子、
IDAError、run_in_main。调用方 `api.decompile(ea)` 等用法零改动。
"""

from .core import IDAError, run_in_main, SEARCH_HARD_LIMIT  # noqa: F401
from .functions import *  # noqa: F401,F403
from .binary import *  # noqa: F401,F403
from .xrefs import *  # noqa: F401,F403
from .names import *  # noqa: F401,F403
from .search import *  # noqa: F401,F403
from .types import *  # noqa: F401,F403
from .hexrays import *  # noqa: F401,F403
from .comments import *  # noqa: F401,F403
from .meta import *  # noqa: F401,F403
from .patch import *  # noqa: F401,F403
