"""Initialize a private shared IPC directory before starting the reader."""

from __future__ import annotations

import errno
import os
import socket
import stat
import sys


IPC_DIRECTORY = "/run/observer-ipc"
API_GROUP_ID = 65532


def secure_ipc_directory(directory: str = IPC_DIRECTORY, gid: int = API_GROUP_ID) -> None:
    """Restrict the dedicated IPC mount to the reader and API service group."""
    if os.geteuid() != 0:
        raise PermissionError("reader IPC initialization requires root")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(directory, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise PermissionError("IPC directory must be a root-owned directory")
        entries = os.listdir(fd)
        if entries:
            if entries != ["reader.sock"]:
                raise FileExistsError("unexpected IPC directory entry")
            entry = os.stat("reader.sock", dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != 0 or
                    entry.st_gid != gid or stat.S_IMODE(entry.st_mode) != 0o660):
                raise PermissionError("untrusted IPC endpoint")
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                try:
                    probe.connect(os.path.join(directory, "reader.sock"))
                except OSError as exc:
                    if exc.errno != errno.ECONNREFUSED:
                        raise
                else:
                    raise FileExistsError("IPC reader already active")
            finally:
                probe.close()
            # The API only has a read-only mount and cannot replace this entry.
            os.unlink("reader.sock", dir_fd=fd)
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o2750)
        final = os.fstat(fd)
        if (final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode)) != (0, gid, 0o2750):
            raise PermissionError("IPC directory permissions were not established")
    finally:
        os.close(fd)


def main() -> None:
    secure_ipc_directory()
    os.execv(sys.executable, [sys.executable, "-m", "infrastructure_observer.service", *sys.argv[1:]])


if __name__ == "__main__":
    main()
