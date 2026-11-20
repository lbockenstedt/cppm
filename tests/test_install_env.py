"""install.sh writes the spoke's .env without losing what a re-run did not set.

The installer used to rewrite .env from scratch on every run with only HUB_URL,
SPOKE_ID and SPOKE_SECRET. A re-run for a code update without flags therefore
reset the PSK to "lm-secret" and the hub to "auto", dropped HUB_SECRET (which was
never written at all) and every setting an admin had added by hand, and left the
file world-readable. These tests run the installer's ".env" block on its own.
"""
import fcntl
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

INSTALL_SH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "install.sh")


def _flock_dir():
    """A directory to put first on PATH holding a flock(1) stand-in, or None
    when the real one is installed. macOS has no flock(1); the shim does what
    `flock FILE CMD...` does: take an exclusive flock on FILE and run CMD
    while holding it."""
    if shutil.which("flock"):
        return None
    shim_dir = tempfile.mkdtemp()
    shim = os.path.join(shim_dir, "flock")
    with open(shim, "w") as f:
        f.write(f"#!{sys.executable}\nimport fcntl, subprocess, sys\n"
                "with open(sys.argv[1], 'a') as lock:\n"
                "    fcntl.flock(lock, fcntl.LOCK_EX)\n"
                "    sys.exit(subprocess.call(sys.argv[2:]))\n")
    os.chmod(shim, 0o755)
    return shim_dir


def _block_cmd(env_file, given):
    """The bash command that runs install.sh's spoke-env block (see _run)."""
    path_dir = _flock_dir()
    src = open(INSTALL_SH, encoding="utf-8").read()
    block = re.search(r"# >>> spoke-env.*?\n(.*?)# <<< spoke-env", src, re.S).group(1)
    # runuser is stubbed (the test is not root): drop "-u svc_lm --" and run the rest.
    prelude = ["set -e", f"ENV_FILE='{env_file}'", "runuser() { shift 3; \"$@\"; }",
               f"SPOKE_ID='{given.pop('SPOKE_ID', 'cppm-testhost')}'"]
    if path_dir:
        prelude.append(f"PATH='{path_dir}':\"$PATH\"")
    for var in ("HUB_URL", "SPOKE_SECRET", "HUB_SECRET"):
        if var in given:
            prelude += [f"{var}='{given[var]}'", f"{var}_GIVEN=1"]
        else:
            prelude += [f"{var}=''", f"{var}_GIVEN=''"]
    return ["bash", "-c", "\n".join(prelude) + "\n" + block]


def _env(env_file):
    """The KEY=VALUE pairs in ``env_file``."""
    return dict(line.split("=", 1) for line in open(env_file).read().splitlines() if "=" in line)


def _run(env_file, **given):
    """Run install.sh's spoke-env block against ``env_file``.

    ``given`` maps a variable (HUB_URL, SPOKE_SECRET, HUB_SECRET) to the value
    of the flag given on this run; any other is treated as not given. SPOKE_ID
    is set before the block from --id or the hostname, so it is always given.
    runuser is stubbed: the test is not root. flock is the real one, or a
    shim on PATH where flock(1) is missing (macOS).
    """
    r = subprocess.run(_block_cmd(env_file, given), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    _run.stdout = r.stdout
    return _env(env_file)


def test_rerun_without_flags_keeps_secrets_hub_and_admin_settings(tmp_path):
    """A plain re-run keeps the PSK, hub, hub secret and hand-added settings.

    The id is rewritten from the hostname, as before, so a renamed clone takes
    its new name."""
    env = tmp_path / ".env"
    env.write_text("HUB_URL=wss://hub.example:443\nSPOKE_ID=cppm-a\nSPOKE_SECRET=s3cret\n"
                   "HUB_SECRET=hs\nCPPM_HOST=cppm.example\nLM_CPPM_VERIFY_TLS=false\n")
    out = _run(env)
    assert out == {"HUB_URL": "wss://hub.example:443", "SPOKE_ID": "cppm-testhost",
                   "SPOKE_SECRET": "s3cret", "HUB_SECRET": "hs",
                   "CPPM_HOST": "cppm.example", "LM_CPPM_VERIFY_TLS": "false"}
    # The installer reports the hub it kept, not the "auto" default.
    assert "Hub Target: wss://hub.example:443" in _run.stdout


def test_given_flags_replace_only_their_own_keys(tmp_path):
    """A flag given on this run wins; the other keys keep their values."""
    env = tmp_path / ".env"
    env.write_text("HUB_URL=wss://old:443\nSPOKE_ID=cppm-a\nSPOKE_SECRET=old\nCPPM_USER=admin\n")
    out = _run(env, SPOKE_ID="cppm-a", SPOKE_SECRET="new=psk", HUB_SECRET="hub-psk")
    assert out["SPOKE_SECRET"] == "new=psk"
    assert out["HUB_SECRET"] == "hub-psk"
    assert out["HUB_URL"] == "wss://old:443"
    assert out["SPOKE_ID"] == "cppm-a"
    assert out["CPPM_USER"] == "admin"


def test_fresh_install_writes_defaults_and_hub_secret(tmp_path):
    """With no .env and no flags the defaults are written, HUB_SECRET included."""
    env = tmp_path / ".env"
    out = _run(env)
    assert out == {"HUB_URL": "auto", "SPOKE_ID": "cppm-testhost",
                   "SPOKE_SECRET": "lm-secret", "HUB_SECRET": ""}


def test_env_file_is_owner_only_and_no_temp_file_is_left(tmp_path):
    """The secrets file is mode 0600 even when it was world-readable before."""
    env = tmp_path / ".env"
    env.write_text("SPOKE_SECRET=s3cret\n")
    env.chmod(0o644)
    _run(env)
    assert stat.S_IMODE(os.stat(env).st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env", ".env.lock"]


def test_installer_creates_the_service_user_before_handing_it_the_repo():
    """svc_lm is created when missing, before the chown that needs it."""
    src = open(INSTALL_SH, encoding="utf-8").read()
    create = src.index("useradd -r -s /bin/false -M svc_lm")
    assert create < src.index('chown -R svc_lm:svc_lm "$INSTALL_DIR/cppm"')


def test_waits_for_the_spokes_env_lock_and_keeps_a_rotated_secret(tmp_path):
    """While the running spoke holds .env.lock (as control_plane does when it
    rotates a secret) the installer waits, then reads the rotated value instead
    of overwriting it with the one it would have read before."""
    env = tmp_path / ".env"
    env.write_text("SPOKE_SECRET=before\nHUB_SECRET=hs-before\n")
    with open(f"{env}.lock", "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        proc = subprocess.Popen(_block_cmd(env, {}), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        # The block takes milliseconds unlocked; it must still be waiting.
        time.sleep(1.0)
        assert proc.poll() is None, "installer did not wait for .env.lock"
        # The spoke rotates both secrets while holding the lock.
        env.write_text("SPOKE_SECRET=rotated\nHUB_SECRET=hs-rotated\n")
        fcntl.flock(held, fcntl.LOCK_UN)
    _, err = proc.communicate(timeout=30)
    assert proc.returncode == 0, err
    out = _env(env)
    assert out["SPOKE_SECRET"] == "rotated" and out["HUB_SECRET"] == "hs-rotated"


def test_env_step_runs_as_the_service_user_and_root_touches_no_path_there():
    """The .env step runs as svc_lm under the spoke's lock. The directory is
    svc_lm's, so root opening, chowning or chmodding a path in it would follow
    a symlink a compromised service account planted there."""
    src = open(INSTALL_SH, encoding="utf-8").read()
    block = re.search(r"# >>> spoke-env.*?\n(.*?)# <<< spoke-env", src, re.S).group(1)
    code = "\n".join(line for line in block.splitlines() if not line.lstrip().startswith("#"))
    assert 'runuser -u svc_lm -- flock "$ENV_FILE.lock" bash -e <<\'SPOKE_ENV\'' in code
    assert "chown" not in code and "chmod" not in code and "exec " not in code
