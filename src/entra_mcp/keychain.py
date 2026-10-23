"""Client secret from the macOS Keychain. Never from a file in the repo.

Order: ENTRA_CLIENT_SECRET environment variable (for CI with its own secret store), then
`security find-generic-password -s <service> -a <account> -w`.
"""
from __future__ import annotations

import os
import subprocess

from .redact import register_secret


class SecretUnavailable(RuntimeError):
    pass


def client_secret(service: str, account: str) -> str:
    value = os.environ.get("ENTRA_CLIENT_SECRET", "")
    if not value:
        try:
            out = subprocess.run(["security", "find-generic-password", "-s", service, "-a", account, "-w"],
                                 capture_output=True, text=True, check=True, timeout=10)
            value = out.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            raise SecretUnavailable(f"no client secret: Keychain item service={service} account={account} "
                                    f"not found and ENTRA_CLIENT_SECRET unset ({type(e).__name__})") from None
    if not value:
        raise SecretUnavailable("client secret is empty")
    register_secret(value)      # every log/audit/error string is scrubbed of it from now on
    return value
