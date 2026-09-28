"""Populate the disposable ext4 image for large directory enumeration."""

import subprocess
import sys
import tempfile


with tempfile.NamedTemporaryFile(mode="w", encoding="ascii") as commands:
    commands.write("mkdir /live-ci/large-directory\n")
    for group in range(2):
        target = f"/live-ci/large-target-{group}"
        commands.write(f"write /dev/null {target}\n")
        for index in range(group * 50000, (group + 1) * 50000):
            if index != 0 and index % 200 == 0:
                commands.write("expand_dir /live-ci/large-directory\n")
            commands.write(f"ln {target} /live-ci/large-directory/entry-{index:06d}\n")
        commands.write(f"set_inode_field {target} links_count 50001\n")
    commands.flush()
    result = subprocess.run(
        ["debugfs", "-w", "-f", commands.name, sys.argv[1]],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    diagnostics = [
        line
        for line in result.stderr.splitlines()
        if line and not line.startswith("debugfs ")
    ]
    if diagnostics:
        raise SystemExit("\n".join(diagnostics))

result = subprocess.run(["e2fsck", "-fyD", sys.argv[1]], check=False)
if result.returncode not in (0, 1):
    raise SystemExit(result.returncode)
