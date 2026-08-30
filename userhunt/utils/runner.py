"""
Shared subprocess runner with streaming output.
- Uses Popen for real-time line-by-line capture
- NEVER loses output on timeout — collects everything captured so far
- Logs to web dashboard in real-time
- Configurable timeouts per tool
"""
import subprocess
import sys
import time
import threading
from typing import List, Optional, Callable, Any


def run_tool(
    cmd: List[str],
    cwd: str = None,
    timeout: int = 300,
    tool_name: str = "unknown",
    on_stdout: Optional[Callable[[str], None]] = None,
    on_stderr: Optional[Callable[[str], None]] = None,
    env: Optional[dict] = None,
) -> tuple[str, str, int]:
    """
    Run a subprocess with streaming output capture.

    Returns (stdout_text, stderr_text, return_code).
    Even if timeout is hit, returns ALL output captured so far.
    """
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    killed = threading.Event()

    def reader(pipe, lines, direction):
        """Read lines from a pipe and collect them."""
        try:
            for line in iter(pipe.readline, ''):
                if not line:
                    break
                text = line.rstrip('\n').rstrip('\r')
                lines.append(text)
                # Log to dashboard in real-time
                try:
                    from userhunt.web.store import store
                    store.tool_log(tool_name, text, direction=direction)
                except Exception:
                    pass
                # Call callback if provided
                if direction == "stdout" and on_stdout:
                    on_stdout(text)
                elif direction == "stderr" and on_stderr:
                    on_stderr(text)
        except Exception:
            pass
        finally:
            try:
                pipe.close()
            except Exception:
                pass

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            text=True,
            bufsize=1,
        )

        # Start reader threads
        t_out = threading.Thread(target=reader, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
        t_err = threading.Thread(target=reader, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
        t_out.start()
        t_err.start()

        # Wait for completion with timeout
        # timeout=0 means NO timeout — wait indefinitely
        if timeout and timeout > 0:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Timeout hit — kill the process but KEEP all captured output
                try:
                    proc.kill()
                except Exception:
                    pass
                # Give threads a moment to finish reading
                t_out.join(timeout=2)
                t_err.join(timeout=2)

                # Log the timeout
                try:
                    from userhunt.web.store import store
                    store.log(
                        f"TIMEOUT after {timeout}s for {tool_name} — keeping captured output",
                        level="warn",
                        source=tool_name,
                    )
                except Exception:
                    pass
        else:
            # No timeout — wait for tool to finish naturally
            try:
                from userhunt.web.store import store
                store.log(
                    f"Running {tool_name} (no timeout — waiting for completion)...",
                    source=tool_name,
                )
            except Exception:
                pass
            proc.wait()  # Blocks until tool finishes

        # Wait for reader threads to finish
        t_out.join(timeout=5)
        t_err.join(timeout=5)

        return (
            "\n".join(stdout_lines),
            "\n".join(stderr_lines),
            proc.returncode or 0,
        )

    except FileNotFoundError:
        # Command not found
        try:
            from userhunt.web.store import store
            store.log(f"NOT FOUND: {cmd[0]}", level="error", source=tool_name)
        except Exception:
            pass
        return ("", f"Command not found: {cmd[0]}", -1)

    except Exception as e:
        try:
            from userhunt.web.store import store
            store.log(f"ERROR: {e}", level="error", source=tool_name)
        except Exception:
            pass
        return ("\n".join(stdout_lines), str(e), -1)

    finally:
        # Ensure process is cleaned up (only if still running)
        if proc and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
            # Wait for reader threads to finish
            try:
                t_out.join(timeout=5)
                t_err.join(timeout=5)
            except Exception:
                pass


def run_tool_simple(
    cmd: List[str],
    cwd: str = None,
    timeout: int = 300,
    tool_name: str = "unknown",
) -> tuple[str, str, int]:
    """Simplified version — just returns (stdout, stderr, returncode)."""
    return run_tool(cmd, cwd=cwd, timeout=timeout, tool_name=tool_name)
