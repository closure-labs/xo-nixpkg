# SPDX-License-Identifier: Apache-2.0
"""Monotonic operation budgets and bounded process-group cleanup."""
from contextlib import contextmanager
from contextvars import ContextVar
import os
import signal
import subprocess
import time
import sys
import threading

DEADLINE = ContextVar('operation_deadline', default=None)
KILL_GRACE = 10


def remaining(limit):
    deadline = DEADLINE.get()
    inherited = os.environ.get('CI_OPERATION_DEADLINE')
    if inherited is not None:
        bound = float(inherited)
        deadline = min(deadline, bound) if deadline is not None else bound
    value = limit if deadline is None else min(limit, deadline - time.monotonic())
    if value <= 0:
        raise subprocess.TimeoutExpired(['bounded-operation'], limit)
    return value


@contextmanager
def budget(seconds, inherit=True):
    parent = DEADLINE.get()
    inherited = os.environ.pop('CI_OPERATION_DEADLINE', None) if not inherit else None
    deadline = time.monotonic() + seconds
    token = DEADLINE.set(min(parent, deadline) if inherit and parent is not None else deadline)
    try:
        yield deadline
    finally:
        DEADLINE.reset(token)
        if inherited is not None:
            os.environ['CI_OPERATION_DEADLINE'] = inherited


def process_identity(pid):
    try:
        # A command name may contain spaces/parentheses. Fields after its final
        # ')' start with state; starttime protects against PID reuse during grace.
        from pathlib import Path
        fields = Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()
        return int(fields[1]), fields[19]
    except (OSError, ValueError, IndexError):
        return None


def descendants(pid):
    from pathlib import Path
    records = {int(path.name): process_identity(int(path.name))
               for path in Path('/proc').iterdir() if path.name.isdecimal()}
    found = {pid: records.get(pid)}
    while True:
        added = {key: value for key, value in records.items()
                 if key not in found and value is not None and value[0] in found}
        if not added:
            return found
        found.update(added)


def signal_family(records, signum):
    for pid, identity in reversed(list(records.items())):
        current = process_identity(pid)
        if identity is not None and current is not None and current[1] == identity[1]:
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass


def terminate(child):
    # Nested supervisors may create their own sessions. Remember their process
    # identities before TERM so even reparented descendants receive the final
    # KILL within the outer supervisor's single 10-second grace period.
    family = descendants(child.pid)
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    signal_family(family, signal.SIGTERM)
    try:
        child.communicate(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired:
        pass
    finally:
        current = process_identity(child.pid)
        original = family.get(child.pid)
        if current is not None and original is not None and current[1] == original[1]:
            family.update({pid: identity for pid, identity in descendants(child.pid).items() if pid not in family})
        signal_family(family, signal.SIGKILL)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.communicate()


def run(args, *, timeout, check=False, capture_output=False, input=None, **kwargs):
    limit = remaining(timeout)
    if capture_output:
        kwargs['stdout'] = kwargs['stderr'] = subprocess.PIPE
    if input is not None:
        kwargs['stdin'] = subprocess.PIPE
    environment = dict(kwargs.pop('env', os.environ))
    environment['CI_OPERATION_DEADLINE'] = str(time.monotonic() + limit)
    with termination_guard():
        return _run(args, limit, input, check, dict(kwargs, env=environment))


@contextmanager
def termination_guard():
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    previous = signal.signal(signal.SIGTERM, interrupted) if threading.current_thread() is threading.main_thread() else None
    try:
        yield
    finally:
        if previous is not None:
            signal.signal(signal.SIGTERM, previous)


def _run(args, limit, input, check, kwargs):
    with subprocess.Popen(args, start_new_session=True, **kwargs) as child:
        try:
            stdout, stderr = child.communicate(input, timeout=limit)
        except BaseException:
            terminate(child)
            raise
        result = subprocess.CompletedProcess(args, child.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=float, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or args.timeout <= 0:
        parser.error('positive timeout and command required')
    try:
        return run(command, timeout=args.timeout).returncode
    except subprocess.TimeoutExpired:
        print('Bounded operation timed out', file=sys.stderr)
        return 124


if __name__ == '__main__':
    sys.exit(main())
