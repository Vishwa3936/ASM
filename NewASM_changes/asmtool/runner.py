"""Subprocess runner: tool discovery, timeouts, and consistent logging.

Every external command in the pipeline goes through CommandRunner so we get
uniform logging, timeout handling, dry-run support, and graceful behaviour
when a tool is missing (instead of a hard crash mid-pipeline).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Sequence, Tuple, Union

log = logging.getLogger("asm.runner")

Candidates = Union[str, Sequence[str]]


class CommandRunner:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self._which_cache: Dict[str, Optional[str]] = {}

    def resolve_binary(self, candidates: Candidates) -> Optional[str]:
        """Return the first resolvable binary path from candidates, or None."""
        names = [candidates] if isinstance(candidates, str) else list(candidates)
        for name in names:
            if name not in self._which_cache:
                self._which_cache[name] = shutil.which(name)
            if self._which_cache[name]:
                return self._which_cache[name]
        return None

    def available(self, candidates: Candidates) -> bool:
        return self.resolve_binary(candidates) is not None

    def run(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        stdin_input: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Run a command. Returns (returncode, stdout, stderr).

        Convention: rc 127 = tool not found, 124 = timeout (like GNU timeout).
        Never raises for these — the caller decides how to degrade.
        """
        printable = " ".join(cmd)
        log.info("RUN  %s", printable)
        if self.dry_run:
            return 0, "", ""

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            log.debug("DONE rc=%s in %.1fs", proc.returncode, time.time() - start)
            if proc.returncode != 0:
                log.debug("stderr: %s", (proc.stderr or "").strip()[:500])
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            log.warning("TIMEOUT after %ss: %s", timeout, printable)
            return 124, exc.stdout or "", exc.stderr or ""
        except FileNotFoundError:
            log.error("Tool not found on PATH: %s", cmd[0])
            return 127, "", "tool not found"
