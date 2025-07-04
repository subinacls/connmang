import os
import subprocess
import json
from datetime import datetime
from .ssh_manager import SSHManager


KEY_STORE_PATH = os.path.expanduser("~/.ssh/connmang_keys/")
KEY_LOG = os.path.join(KEY_STORE_PATH, "keys.json")
os.makedirs(KEY_STORE_PATH, exist_ok=True)

def list_keys(alias):
    result = []
    alias_dir = os.path.join(KEY_STORE_PATH, alias)
    if not os.path.isdir(alias_dir):
        return result

    for fname in os.listdir(alias_dir):
        if fname.endswith(".pub"):
            full_path = os.path.join(alias_dir, fname)
            stat = os.stat(full_path)
            created = datetime.fromtimestamp(stat.st_mtime).isoformat()
            result.append({
                "name": fname.replace(".pub", ""),
                "type": fname.split("_")[1].replace(".pub", ""),
                "comment": "",  # Optionally parse from pubkey
                "created": created,
                "public": full_path
            })
    return result

def install_key_to_remote(alias, pubkey, privkey):
    ssh_mgr = SSHManager()
    profile = ssh_mgr.profiles.get(alias)
    if not profile:
        return False

    ssh_mgr.connect(
        alias=alias,
        host=profile["host"],
        port=profile.get("port", 22),
        username=profile["username"],
        password=profile.get("password"),
        key_file=profile.get("key_file")
    )

    client = ssh_mgr.sessions.get(alias)
    if not client:
        return False

    try:
        sftp = client.open_sftp()
        ssh_dir = f"/home/{profile['username']}/.ssh"
        connmang_dir = f"{ssh_dir}/connmang"
        authorized_keys = f"{ssh_dir}/authorized_keys"
        remote_pub = f"{connmang_dir}/id_connmang.pub"
        remote_priv = f"{connmang_dir}/id_connmang"

        # Create dirs if needed
        try:
            sftp.stat(connmang_dir)
        except FileNotFoundError:
            sftp.mkdir(connmang_dir)

        # Write private key (mode 600)
        with sftp.open(remote_priv, "w") as f:
            f.write(privkey + "\n")
        sftp.chmod(remote_priv, 0o600)

        # Write public key (mode 644)
        with sftp.open(remote_pub, "w") as f:
            f.write(pubkey + "\n")
        sftp.chmod(remote_pub, 0o644)

        # Append public key to authorized_keys if not present
        try:
            with sftp.open(authorized_keys, "r") as f:
                existing = f.read()
        except IOError:
            existing = ""

        if pubkey not in existing:
            with sftp.open(authorized_keys, "a") as f:
                f.write(pubkey + "\n")

        sftp.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to install keys: {e}")
        return False


def generate_ssh_key(alias, key_type="ed25519", comment="", passphrase=""):
    from datetime import datetime
    import os
    import subprocess

    key_dir = os.path.join(KEY_STORE_PATH, alias)
    os.makedirs(key_dir, exist_ok=True)

    timestamp = int(datetime.now().timestamp())
    key_filename = f"{alias}_{key_type}_{timestamp}"
    priv_path = os.path.join(key_dir, key_filename)
    pub_path = priv_path + ".pub"

    cmd = [
        "ssh-keygen", "-t", key_type,
        "-f", priv_path,
        "-q", "-N", passphrase
    ]
    if comment:
        cmd.extend(["-C", comment])

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise RuntimeError(f"[ssh-keygen ERROR] {result.stderr.decode()}")

    return priv_path, pub_path

def log_key(alias, comment, key_type, private_path, public_path, remote=None):
    record = {
        "alias": alias,
        "comment": comment,
        "type": key_type,
        "private": private_path,
        "public": public_path,
        "remote": remote,
        "created": datetime.now().isoformat(),
    }
    if os.path.exists(KEY_LOG):
        with open(KEY_LOG) as f:
            db = json.load(f)
    else:
        db = []
    db.append(record)
    with open(KEY_LOG, "w") as f:
        json.dump(db, f, indent=2)