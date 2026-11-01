"""Isola o estado do lib/mask.py entre testes: o módulo é global e o setup() troca sys.stdout/sys.stderr."""

import contextlib
import os
import sys
from unittest import mock

from lib import mask

TEST_KEY = b"chave-fixa-dos-testes-0123456789abcdef"  # nada de outputs/.mask-key durante os testes


@contextlib.contextmanager
def isolated(env=None):
    saved = (sys.stdout, sys.stderr, mask._KEY, mask._ENABLED, mask._KEEP_PREFIXES,
             dict(mask._LEARNED), set(mask._ALIASES))
    mask._KEY, mask._ENABLED, mask._KEEP_PREFIXES = TEST_KEY, True, ()
    mask._LEARNED.clear()
    mask._ALIASES.clear()
    environ = {k: v for k, v in os.environ.items() if k != mask.ENV_FLAG}
    environ.update(env or {})
    try:
        with mock.patch.dict(os.environ, environ, clear=True):
            yield
    finally:
        sys.stdout, sys.stderr = saved[0], saved[1]
        mask._KEY, mask._ENABLED, mask._KEEP_PREFIXES = saved[2], saved[3], saved[4]
        mask._LEARNED.clear()
        mask._LEARNED.update(saved[5])
        mask._ALIASES.clear()
        mask._ALIASES.update(saved[6])
