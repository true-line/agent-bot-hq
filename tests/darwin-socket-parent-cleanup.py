"""Exercise comparison teardown using temporary sockets and simulated launchd replies."""

import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("comparison", Path(__file__).with_name("darwin-socket-parents.py"))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class Cleanup(unittest.TestCase):
    def exercise(self, scenario):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            stage = Path(tmp)
            parent = stage / "parent"
            parent.mkdir()
            parent_id = parent.lstat()
            anchor, plist = stage / "anchor", stage / "job.plist"
            anchor.touch()
            os.link(anchor, plist)
            endpoint = parent / "test.sock"
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(endpoint))
                socket_id = endpoint.lstat()
                if scenario == "replaced plist":
                    plist.unlink()
                    plist.symlink_to(anchor)
                elif scenario == "replaced parent":
                    parent.rename(stage / "original")
                    parent.mkdir()
                elif scenario == "replaced socket":
                    endpoint.rename(parent / "original.sock")
                    with socket.socket(socket.AF_UNIX) as replacement:
                        replacement.bind(str(endpoint))
                elif scenario == "unobserved socket":
                    socket_id = None
                elif scenario == "failed bootstrap":
                    endpoint.unlink()
                loaded = scenario not in ("failed bootstrap", "uncertain bootstrap")
                refused = scenario not in ("successful stop", "failed bootstrap")
                with patch.object(comparison, "fixture_job") as job, patch.object(comparison, "sudo") as remove:
                    if scenario in ("uncertain bootstrap", "unverified job"):
                        job.side_effect = subprocess.CalledProcessError(1, "fixture")
                    def unlink(command, path):
                        self.assertEqual(command, "/bin/rm")
                        path.unlink()
                    remove.side_effect = unlink
                    args = ("job", plist, anchor, endpoint, parent_id, socket_id, loaded)
                    if refused:
                        with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
                            comparison.clean_trial(*args)
                        remove.assert_not_called()
                    else:
                        comparison.clean_trial(*args)
                        self.assertFalse(os.path.lexists(endpoint))
                    self.assertEqual(anchor.exists(), refused)
                    if scenario == "replaced plist":
                        job.assert_not_called()
                    elif loaded:
                        job.assert_called_once_with("fixture_stop_job", "job", str(plist))
                    else:
                        job.assert_called_once_with("fixture_job_absent", "job")

    def test_cleanup(self):
        for scenario in ("successful stop", "failed bootstrap", "uncertain bootstrap", "unverified job",
                         "replaced plist", "replaced parent", "replaced socket", "unobserved socket"):
            with self.subTest(scenario=scenario):
                self.exercise(scenario)


if __name__ == "__main__":
    unittest.main()
