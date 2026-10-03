"""Monotonic operation budgets shared by synchronous nested Dynamic operations."""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import inspect
import math
import subprocess
import time

_CURRENT = ContextVar('dynamic_operation_deadline', default=None)


class Deadline:
    def __init__(self, seconds, clock=time.monotonic):
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("Deadline must be finite and nonnegative")
        self.clock = clock
        self.end = clock() + seconds

    def remaining(self):
        return max(0.0, self.end - self.clock())

    def timeout(self, ceiling):
        remaining = min(float(ceiling), self.remaining())
        if remaining <= 0:
            raise subprocess.TimeoutExpired('dynamic_operation_deadline', 0)
        return remaining


def current_deadline():
    return _CURRENT.get()


def bounded_timeout(ceiling):
    deadline = current_deadline()
    return deadline.timeout(ceiling) if deadline else ceiling


@contextmanager
def budget(seconds, clock=time.monotonic, deadline=None):
    parent = current_deadline()
    if deadline:
        clock = deadline.clock
        seconds = min(seconds, deadline.remaining())
    if parent:
        clock = parent.clock
        seconds = min(seconds, parent.remaining())
    child = Deadline(seconds, clock)
    if parent:
        child.end = min(child.end, parent.end)
    if deadline and deadline.clock is child.clock:
        child.end = min(child.end, deadline.end)
    token = _CURRENT.set(child)
    try:
        yield child
    finally:
        _CURRENT.reset(token)


def bounded_operation(default, field=None, self_field=None, limits_field=None):
    def decorate(fn):
        signature = inspect.signature(fn)
        @wraps(fn)
        def wrapped(*args, **kwargs):
            explicit = kwargs.pop('deadline', None)
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            values = bound.arguments
            seconds = values.get(field, default) if field else default
            if self_field:
                seconds = getattr(values['self'], self_field)
            if limits_field and values.get('limits') is not None:
                seconds = getattr(values['limits'], limits_field)
            with budget(seconds, values.get('clock', time.monotonic), explicit):
                return fn(*args, **kwargs)
        return wrapped
    return decorate
