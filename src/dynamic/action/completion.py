"""Bounded observation of action postconditions; no input dispatch or causal claim."""
from dataclasses import dataclass
import time
from src.dynamic.deadline import budget
from src.dynamic.ui.models import ScreenObservation


@dataclass
class ActionCompletion:
    observation: object = None
    runtime: object = None
    condition: str = 'unconfirmed'
    attempts: int = 0

    @property
    def confirmed(self):
        return self.condition != 'unconfirmed'


def wait_for_completion(observer, source, *, runtime_observer=None, before_runtime=None,
                        target_package='', no_navigation=None, timeout_seconds=4.0,
                        clock=time.monotonic, sleeper=time.sleep, max_attempts=8):
    result = ActionCompletion()
    with budget(timeout_seconds, clock) as deadline:
        while deadline.remaining() > 0 and result.attempts < max_attempts:
            result.attempts += 1
            try:
                obs = observer()
                if not isinstance(obs, ScreenObservation):
                    raise ValueError("Invalid post-action UI observation")
                if deadline.remaining() <= 0:
                    break
                result.observation = obs
                if obs.is_dialog_or_system and (not getattr(source, 'is_dialog_or_system', False) or obs.screen_identity != source.screen_identity):
                    result.condition = 'dialog_observed'
                elif obs.screen_identity != source.screen_identity or obs.foreground_activity != getattr(source, 'activity', obs.foreground_activity):
                    result.condition = 'ui_state_changed'
                elif no_navigation and no_navigation(obs):
                    result.condition = 'explicit_no_navigation_postcondition'
                if result.confirmed:
                    return result
            except Exception:
                result.observation = None
            if runtime_observer and deadline.remaining() > 0:
                try:
                    result.runtime = runtime_observer.observe(target_package)
                    if deadline.remaining() > 0 and before_runtime:
                        pid_changed = result.runtime.pid is not None and result.runtime.pid != before_runtime.pid
                        activity_changed = bool(result.runtime.foreground_activity and before_runtime.foreground_activity
                                                and result.runtime.foreground_activity != before_runtime.foreground_activity)
                        if pid_changed or activity_changed or result.runtime.crash_detected:
                            result.condition = 'runtime_state_changed'
                            return result
                except Exception:
                    pass
            if deadline.remaining() > 0:
                sleeper(min(0.1, deadline.remaining()))  # pacing, never readiness
    return result
