import os
import subprocess
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from lib.CommandExecutor import CommandExecutor


def test_monitor_process_returns_three_values():
    executor = CommandExecutor()
    process = subprocess.Popen(['bash', '-c', 'echo ok'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    success, output, error = executor._monitor_process(process, 5)
    assert success is True
    assert output.strip() == 'ok'
    assert error == ''


def test_execute_command_success_and_failure():
    executor = CommandExecutor()
    # Successful command
    result = executor.execute_command('echo', args=['hello'])
    assert result.success is True
    assert result.output.strip() == 'hello'
    assert result.error == ''

    # Failing command with stderr output
    result_fail = executor.execute_command('bash', args=['-c', 'echo err >&2; exit 1'])
    assert result_fail.success is False
    assert result_fail.error.strip() == 'err'
