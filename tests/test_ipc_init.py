"""IPC mount ownership, membership, and safe restart behavior."""

from __future__ import annotations

import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from infrastructure_observer.ipc_init import secure_ipc_directory


class IPCSecurityTests(unittest.TestCase):
    def test_unprivileged_initialization_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("infrastructure_observer.ipc_init.os.geteuid", return_value=1000):
                with self.assertRaises(PermissionError):
                    secure_ipc_directory(directory)

    @unittest.skipUnless(os.geteuid() == 0, "requires isolated root-owned test directory")
    def test_group_restriction_and_safe_stale_socket_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            gid = os.getegid()
            secure_ipc_directory(directory, gid)
            info = os.stat(directory)
            self.assertEqual((info.st_uid, info.st_gid), (0, gid))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o2750)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            path = str(Path(directory) / "reader.sock")
            sock.bind(path)
            os.chmod(path, 0o660)
            sock.close()
            secure_ipc_directory(directory, gid)
            self.assertFalse(os.path.lexists(path))

    @unittest.skipUnless(os.geteuid() == 0, "requires isolated root-owned test directory")
    def test_active_or_unexpected_ipc_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            gid = os.getegid()
            secure_ipc_directory(directory, gid)
            path = str(Path(directory) / "reader.sock")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(path)
                os.chmod(path, 0o660)
                sock.listen(1)
                with self.assertRaises(FileExistsError):
                    secure_ipc_directory(directory, gid)
            finally:
                sock.close()
                os.unlink(path)
            (Path(directory) / "unapproved-file").write_text("data")
            with self.assertRaises(FileExistsError):
                secure_ipc_directory(directory, gid)

    @unittest.skipUnless(os.geteuid() == 0, "requires isolated root-owned test directory")
    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(OSError):
                secure_ipc_directory(str(link), os.getegid())
