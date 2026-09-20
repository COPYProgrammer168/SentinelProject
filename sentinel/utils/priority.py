"""Process priority utility to keep Sentinel lightweight and unobtrusive."""

from __future__ import annotations
import os
import sys
import psutil
from sentinel.utils import logger


def set_low_priority() -> bool:
    """Set current process to low/below-normal priority."""
    try:
        p = psutil.Process(os.getpid())
        if sys.platform == "win32":
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            logger.debug("Set process priority to BELOW_NORMAL_PRIORITY_CLASS (Windows)", enabled=True)
            return True
        else:
            # Unix / macOS
            try:
                os.nice(10)
                logger.debug("Set process nice level to 10 (Unix)", enabled=True)
                return True
            except AttributeError:
                p.nice(10)
                return True
    except Exception as e:
        logger.warn(f"Failed to lower process priority: {e}")
        return False
