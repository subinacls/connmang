import paramiko
import os
import subprocess
import uuid
import logging

SESSION_DIR = "/tmp/ssh_sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

class SSHManager:
    """
    Initializes the SSHManager with dictionaries to manage SSH sessions and shell channels.
    """
    def __init__(self):
        self.sessions = {}  # key: alias, value: paramiko.SSHClient
        self.shells = {}  # key: alias, value: invoke_shell() channel

    def start_session(self, alias, config, elevate=False, background=False, session_name=None):
        """
        Starts a new SSH session in a separate xterm window based on the provided configuration.

        Args:
            alias (str): A unique identifier for the SSH session.
            config (dict): A dictionary containing SSH connection parameters and options.
        """

        port = config.get("port", str(22))
        username = config.get("username")
        host = config.get("host")

        # Build base SSH command
        cmd = ["xterm", "-T", f"SSH: {alias}", "-e", "ssh"]

        # Jump host (-J)
        jump = config.get("jumpHost")
        if jump:
            #cmd += ["-o", f"ProxyCommand=ssh -W %h:%p {jump}"]
            cmd.append("-J")
            cmd.append(str(jump))

        key_text = config.get("key_text", "").strip()
        key_file = config.get("key_file")

        if key_text:
            temp_key_path = os.path.join(SESSION_DIR, f"{alias}_id.key")
            with open(temp_key_path, "w") as keyfile:
                keyfile.write(key_text)
            os.chmod(temp_key_path, 0o600)
            cmd.append("-i")
            cmd.append(str(temp_key_path))
        elif key_file:
            cmd.append("-i")
            cmd.append(str(key_file))

        # Gateway ports
        if config.get("gatewayPorts"):
            cmd.append("-g")
        # Compression (-C)
        if config.get("compression"):
            cmd.append("-C")
        # Agent forwarding (-A)
        if config.get("agentForwarding"):
            cmd.append("-A")
        # X11 forwarding (-X)
        if config.get("x11Forwarding"):
            cmd.append("-X")
        # Local forwarding
        lf = config.get("localForward")
        if lf:
            cmd.append("-L")
            cmd.append(str(lf))
        # Remote forwarding
        rf = config.get("remoteForward")
        if rf:
            cmd.append("-R")
            cmd.append(str(rf))
        print(" ".join(cmd))
        # SOCKS5 proxy
        dp = config.get("socksProxy")
        if dp:
            cmd.append("-D")
            cmd.append(str(dp))
        print(" ".join(cmd))
        # Custom -o options (space-separated list of Option=Value)
        custom_opts = config.get("customOptions", "")
        if custom_opts:
            for opt in custom_opts.strip().split():
                cmd.append("-o")
                cmd.append(str(opt))
        print(" ".join(cmd))
        # Add user@host and port
        cmd.append("-p")
        cmd.append(str(port))
        cmd.append(f"{username}@{host}")

        # Elevate via sudo -i if requested
        if elevate:
            cmd.append("-t")
            cmd.append("sudo -i")

        logging.info(f"[{alias}] Launching SSH command: {' '.join(cmd)}")
        print(" ".join(cmd))

        if background:
            subprocess.Popen(cmd)
        else:
            subprocess.run(cmd)


    def attach_session(self, alias):
        """
        Placeholder method for attaching to an existing session.

        Args:
            alias (str): Alias of the session to attach to.
        """
        # Placeholder for attach functionality
        print(f"Attach requested for {alias}")





    def connect(self, alias, host, port=22, username=None, password=None, key_file=None):
        """
        Establishes an SSH connection and stores the session.

        Args:
            alias (str): Unique identifier for the session.
            host (str): Target hostname or IP.
            port (int): SSH port (default is 22).
            username (str): SSH username.
            password (str): Optional password.
            key_file (str): Optional path to a private key file.
        """
        if alias in self.sessions:
            raise Exception(f"Alias '{alias}' already in use.")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_file:
            pkey = paramiko.RSAKey.from_private_key_file(key_file)
            client.connect(hostname=host, port=port, username=username, pkey=pkey)
        else:
            client.connect(hostname=host, port=port, username=username, password=password)

        self.sessions[alias] = client
        print(f"[+] Connected to {host} as {username}")

    def open_shell(self, alias, elevate=False):
        """
        Opens an interactive shell session.

        Args:
            alias (str): Session alias to open shell on.
            elevate (bool): If True, elevates to root using sudo.
        """
        if alias in self.shells:
            raise Exception(f"{alias} already has an interactive shell open. Cannot launch another.")

        client = self.sessions.get(alias)
        if not client:
            raise Exception("No active session found for alias.")

        channel = client.invoke_shell()
        print("[+] Shell opened. Interactive session begins.")

        self.shells[alias] = channel

        if elevate:
            channel.send("sudo -i\n")

        # Attach local stdin/stdout to remote shell
        import termios, tty, sys, select
        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            channel.settimeout(0.0)
            while True:
                r, w, e = select.select([channel, sys.stdin], [], [])
                if sys.stdin in r:
                    data = sys.stdin.read(1)
                    if not data:
                        break
                    channel.send(data)
                if channel in r:
                    try:
                        x = channel.recv(1024)
                        if not x:
                            break
                        sys.stdout.write(x.decode())
                        sys.stdout.flush()
                    except Exception:
                        pass
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)

    def open_sftp(self, alias):
        """
        Starts an SFTP session for file transfers over the existing SSH connection.

        Args:
            alias (str): Session alias.
        """
        client = self.sessions.get(alias)
        if not client:
            raise Exception("No active session found for alias.")

        sftp = client.open_sftp()
        print("[+] SFTP session opened. Type 'exit' to quit.")

        while True:
            try:
                cmd = input("sftp> ").strip()
                if cmd == "exit":
                    break
                elif cmd.startswith("get "):
                    _, remote_path = cmd.split(maxsplit=1)
                    filename = os.path.basename(remote_path)
                    sftp.get(remote_path, filename)
                    print(f"[+] Downloaded {filename}")
                elif cmd.startswith("put "):
                    _, local_path = cmd.split(maxsplit=1)
                    filename = os.path.basename(local_path)
                    sftp.put(local_path, filename)
                    print(f"[+] Uploaded {filename}")
                elif cmd == "ls":
                    for f in sftp.listdir():
                        print(f)
                elif cmd.startswith("cd "):
                    _, path = cmd.split(maxsplit=1)
                    sftp.chdir(path)
                elif cmd == "pwd":
                    print(sftp.getcwd())
                else:
                    print("[-] Unknown SFTP command.")
            except Exception as e:
                print(f"[-] Error: {e}")

        sftp.close()

    def background_shell(self, alias, elevate=False):
        """
        Opens a background shell session in tmux.

        Args:
            alias (str): Alias of the session.
            elevate (bool): If True, starts the shell with sudo -i.
        """
        client = self.sessions.get(alias)
        if not client:
            raise Exception("No active session found for alias.")

        session = client.get_transport().open_session()
        session.get_pty()
        if elevate:
            session.exec_command("sudo -i")
        else:
            session.exec_command("/bin/bash")

        # Attach to tmux session
        local_tmux = f"{alias}_bg"
        subprocess.run([
            "tmux", "new-session", "-d", "-s", local_tmux,
            f"ssh {client.get_transport().get_username()}@{client.get_transport().getpeername()[0]}"
        ])
        print(f"[+] Background shell started in tmux session '{local_tmux}'.")

    def close(self, alias):
        """
        Closes the SSH session and removes it from the internal store.

        Args:
            alias (str): Alias of the session to close.
        """
        if alias in self.sessions:
            self.sessions[alias].close()
            del self.sessions[alias]
            print(f"[+] Session '{alias}' closed.")
        else:
            print("[-] Alias not found.")

    def is_connected(self, alias):
        """
        Checks if a session is connected and the transport is active.

        Args:
            alias (str): Alias of the session to check.

        Returns:
            bool: True if session is active, False otherwise.
        """
        client = self.sessions.get(alias)
        if not client:
            return False
        transport = client.get_transport()
        return transport is not None and transport.is_active()

    def list_connected_aliases(self):
        """
        Lists all currently connected session aliases.

        Returns:
            list: A list of connected aliases.
        """
        return [alias for alias, client in self.sessions.items()
                if client.get_transport() and client.get_transport().is_active()]

    def get_sftp(self, alias):
        """
        Retrieves or opens a new SFTP session for the given alias.

        Args:
            alias (str): Session alias.

        Returns:
            paramiko.SFTPClient: The SFTP client instance.
        """
        if alias not in self.sessions:
            raise ValueError(f"No active session for alias: {alias}")
        client = self.sessions[alias]
        if not hasattr(client, "_sftp_client") or client._sftp_client is None:
            client._sftp_client = client.open_sftp()
        return client._sftp_client

    def inject_authorized_key(self, ssh_client, public_key: str):
        """
        Adds a public key to the authorized_keys file on the remote server if it doesn't already exist.

        Args:
            ssh_client (paramiko.SSHClient): An active SSH client.
            public_key (str): The public key string to inject.

        Returns:
            str: 'injected' if added, 'exists' if already present.
        """
        escaped_key = public_key.replace('"', '\\"')
        check_cmd = f'grep -qxF "{escaped_key}" ~/.ssh/authorized_keys'
        append_cmd = (
            f'mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
            f'echo "{escaped_key}" >> ~/.ssh/authorized_keys && '
            f'chmod 600 ~/.ssh/authorized_keys'
        )

        stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
        if stdout.channel.recv_exit_status() != 0:
            ssh_client.exec_command(append_cmd)
            return "injected"
        else:
            return "exists"

    '''
    def run_command(self, alias, command: str):
        """
        Executes a shell command over SSH and returns the output.

        Args:
            alias (str): Session alias.
            command (str): Shell command to execute.

        Returns:
            dict: Contains 'output' and 'error' keys with respective string results.
        """
        if alias not in self.sessions:
            raise Exception("No active session found for alias.")
        client = self.sessions[alias]
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        return {"output": output, "error": error}
    '''

    def run_command(self, alias, command: str):
        """
        Executes a shell command over SSH and returns the output.
        Uses a separate SSHClient instance to avoid conflict with invoke_shell.
        """
        if alias not in self.sessions:
            raise Exception("No active session found for alias.")

        base_client = self.sessions[alias]
        peer_host, port = base_client.get_transport().getpeername()[0], base_client.get_transport().getpeername()[1]
        username = base_client.get_transport().get_username()

        temp_alias = f"{alias}__exec"
        temp_client = paramiko.SSHClient()
        temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Reuse auth method from original client
            if hasattr(base_client._transport, '_preferred_auth') and 'publickey' in base_client._transport._preferred_auth:
                # Key-based reuse not possible directly, assume agent or key_file
                temp_client.connect(hostname=peer_host, port=port, username=username)
            else:
                raise Exception("run_command: Auth method not reusable. Use separate credentials.")

            stdin, stdout, stderr = temp_client.exec_command(command)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
        finally:
            temp_client.close()

        return {"output": output, "error": error}

    '''
    def run_b64_script(self, alias, b64_script: str):
        """
        Executes a base64-encoded shell script remotely.

        Args:
            alias (str): Session alias.
            b64_script (str): Base64-encoded script content.

        Returns:
            dict: Contains 'output' and 'error' keys with results from script execution.
        """
        if alias not in self.sessions:
            raise Exception("No active session found for alias.")
        client = self.sessions[alias]
        script_content = base64.b64decode(b64_script).decode()

        # Write script to remote temp file
        filename = f"/tmp/{uuid.uuid4().hex}.sh"
        commands = f"echo {b64_script} | base64 -d > {filename} && chmod +x {filename} && bash {filename}; rm -f {filename}"

        stdin, stdout, stderr = client.exec_command(commands)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        return {"output": output, "error": error}
    '''

    def run_b64_script(self, alias, b64_script: str):
        """
        Executes a base64-encoded shell script remotely.
        Uses a separate SSHClient instance to avoid conflict with invoke_shell.
        """
        if alias not in self.sessions:
            raise Exception("No active session found for alias.")

        base_client = self.sessions[alias]
        peer_host, port = base_client.get_transport().getpeername()[0], base_client.get_transport().getpeername()[1]
        username = base_client.get_transport().get_username()

        temp_client = paramiko.SSHClient()
        temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            temp_client.connect(hostname=peer_host, port=port, username=username)
            filename = f"/tmp/{uuid.uuid4().hex}.sh"
            commands = f"echo {b64_script} | base64 -d > {filename} && chmod +x {filename} && bash {filename}; rm -f {filename}"
            stdin, stdout, stderr = temp_client.exec_command(commands)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
        finally:
            temp_client.close()

        return {"output": output, "error": error}