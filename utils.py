import subprocess

def run_command(command, capture_output=True, timeout=None):
    """Execute shell command and return output or error as a string.
    
    Args:
        command (str): The command to execute.
        capture_output (bool): Whether to capture stdout and stderr.
        timeout (float, optional): Timeout in seconds for the command execution.
    
    Returns:
        str: Combined stdout or error message if capture_output is True, empty string otherwise.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=capture_output,
            text=True,
            check=True,
            timeout=timeout
        )
        return result.stdout if capture_output else ""
    except subprocess.TimeoutExpired:
        return f"Command '{command}' timed out after {timeout} seconds."
    except subprocess.CalledProcessError as e:
        error_msg = f"Command '{command}' failed: {e.stderr if capture_output else 'Unknown error'}"
        return error_msg
    except Exception as e:
        error_msg = f"Error executing command '{command}': {str(e)}"
        return error_msg