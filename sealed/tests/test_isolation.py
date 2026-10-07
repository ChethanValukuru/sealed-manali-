"""Objective 02 — isolation / no information leakage (Phase 2 / M2).

All assertions are made from INSIDE the red container against the running stack:
  - red can reach the broker (its only permitted peer);
  - red CANNOT open a TCP connection to blue, model, or audit;
  - a seccomp-disallowed syscall (chmod) is blocked;
  - red's rootfs is read-only;
  - red has no capabilities (cap_drop ALL);
  - red cannot see blue/model processes (PID namespace isolation);
  - red cannot read blue/model filesystem paths (mount namespace isolation).

Run on the VM after `make up`:  make test   (or pytest tests/test_isolation.py -v)
"""
from __future__ import annotations

from conftest import compose_exec, requires_stack

# ---- network segmentation ---------------------------------------------------

_CONNECT = (
    "import socket,sys\n"
    "s=socket.socket(); s.settimeout(3)\n"
    "try:\n"
    "    s.connect((%r,%d)); print('CONNECTED'); sys.exit(0)\n"
    "except Exception as e:\n"
    "    print('REFUSED', e); sys.exit(7)\n"
)


@requires_stack
def test_red_can_reach_broker():
    r = compose_exec("red", _CONNECT % ("broker", 8000))
    assert r.returncode == 0, f"red should reach broker: {r.stdout}{r.stderr}"
    assert "CONNECTED" in r.stdout


@requires_stack
def test_red_cannot_reach_blue():
    r = compose_exec("red", _CONNECT % ("blue", 8003))
    assert r.returncode == 7, f"red must NOT reach blue: {r.stdout}{r.stderr}"


@requires_stack
def test_red_cannot_reach_model():
    r = compose_exec("red", _CONNECT % ("model", 8002))
    assert r.returncode == 7, f"red must NOT reach model: {r.stdout}{r.stderr}"


@requires_stack
def test_red_cannot_reach_audit():
    # Invariant 5: tenants have no read path to the audit store.
    r = compose_exec("red", _CONNECT % ("audit", 8001))
    assert r.returncode == 7, f"red must NOT reach audit: {r.stdout}{r.stderr}"


# ---- seccomp ----------------------------------------------------------------

@requires_stack
def test_seccomp_blocks_chmod():
    script = (
        "import os,sys,tempfile\n"
        "p=tempfile.mkstemp()[1]\n"           # file owned by our uid, in /tmp tmpfs
        "try:\n"
        "    os.chmod(p,0o600); print('CHMOD_OK'); sys.exit(0)\n"
        "except OSError as e:\n"
        "    print('BLOCKED', e.errno); sys.exit(8)\n"
    )
    r = compose_exec("red", script)
    assert r.returncode == 8, f"seccomp should block chmod: {r.stdout}{r.stderr}"
    assert "BLOCKED 1" in r.stdout  # EPERM from the profile's errnoRet


# ---- read-only rootfs -------------------------------------------------------

@requires_stack
def test_rootfs_read_only():
    script = (
        "import sys\n"
        "try:\n"
        "    open('/app/evil','w').write('x'); print('WROTE'); sys.exit(0)\n"
        "except OSError as e:\n"
        "    print('RO', e.errno); sys.exit(9)\n"
    )
    r = compose_exec("red", script)
    assert r.returncode == 9, f"rootfs should be read-only: {r.stdout}{r.stderr}"


# ---- capabilities -----------------------------------------------------------

@requires_stack
def test_all_capabilities_dropped():
    script = (
        "import sys\n"
        "cap='?'\n"
        "for line in open('/proc/self/status'):\n"
        "    if line.startswith('CapEff'):\n"
        "        cap=line.split()[1]\n"
        "print(cap); sys.exit(0 if int(cap,16)==0 else 10)\n"
    )
    r = compose_exec("red", script)
    assert r.returncode == 0, f"CapEff must be zero (cap_drop ALL): {r.stdout}{r.stderr}"


# ---- PID namespace isolation ------------------------------------------------

@requires_stack
def test_cannot_see_other_tenant_processes():
    script = (
        "import os\n"
        "names=[]\n"
        "for pid in os.listdir('/proc'):\n"
        "    if pid.isdigit():\n"
        "        try: names.append(open(f'/proc/{pid}/cmdline','rb').read().decode('latin1'))\n"
        "        except Exception: pass\n"
        "joined=' '.join(names)\n"
        "print('filter:app' in joined, 'wrapper:app' in joined)\n"
    )
    r = compose_exec("red", script)
    assert r.returncode == 0
    # Blue runs 'filter:app', model runs 'wrapper:app'; neither is visible to red.
    assert "False False" in r.stdout, f"red must not see other tenants: {r.stdout}"


# ---- mount namespace / filesystem isolation ---------------------------------

@requires_stack
def test_cannot_read_other_tenant_files():
    """Red has its own mount namespace and no shared volume with blue/model, so
    their code is simply not present in red's filesystem — there is no path to
    read. We assert red sees its own app file but not the other tenants'."""
    script = (
        "import os\n"
        "app=set(os.listdir('/app'))\n"
        "print('harness', 'harness.py' in app)\n"   # red's own code: present
        "print('filter', 'filter.py' in app)\n"     # blue's code: absent
        "print('wrapper', 'wrapper.py' in app)\n"    # model's code: absent
    )
    r = compose_exec("red", script)
    assert r.returncode == 0, f"{r.stdout}{r.stderr}"
    assert "harness True" in r.stdout
    assert "filter False" in r.stdout, f"blue's files must be unreachable: {r.stdout}"
    assert "wrapper False" in r.stdout, f"model's files must be unreachable: {r.stdout}"
