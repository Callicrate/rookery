from __future__ import annotations

from contextlib import nullcontext
import hashlib
import os
import runpy
import stat
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

from tests.rookery.env_fixtures import replace_env_assignments
from tests.rookery.test_acceptance_campaign import make_deployed_workspace


def scoped() -> dict[str, object]:
    return {
        "acknowledged": True,
        "generation": 1,
        "expires_at": "unknown",
        "allowed_hosts": ["fixture.invalid"],
        "allowed_cidrs": [],
        "allowed_ports": [],
        "allowed_protocols": ["https", "wss"],
        "allowed_file_origins": [],
        "platform_hosts": ["fixture.invalid"],
        "max_attachment_bytes": 4096,
    }


def fake_binding(scope: dict[str, object]):
    return types.SimpleNamespace(
        scope=scope,
        scope_generation=int(scope["generation"]),
        stop_generation=0,
        file_sha256="a" * 64,
        content_sha256="b" * 64,
        launch_binding_sha256="c" * 64,
    )


def snapshot_tree(root: Path) -> dict[str, tuple[str, int, str]]:
    """Capture entry type, mode, and content identity without following links."""

    snapshot: dict[str, tuple[str, int, str]] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                snapshot[relative] = ("directory", mode, "")
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                snapshot[relative] = (
                    "file",
                    mode,
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            elif stat.S_ISLNK(info.st_mode):
                snapshot[relative] = ("symlink", mode, os.readlink(path))
            else:
                snapshot[relative] = ("special", mode, "")
    return snapshot


@unittest.skipUnless(os.name == "posix", "private-mode contract requires POSIX")
class ImmersiveOutdirSafetyTests(unittest.TestCase):
    def load_capture(self, root: Path) -> tuple[dict[str, object], dict[str, object]]:
        namespace = runpy.run_path(
            str(root / "adapters/immersive/bin/immersive-cluster-capture")
        )
        globals_dict = namespace["main"].__globals__
        globals_dict["ROOT"] = root
        return namespace, globals_dict

    def test_invalid_targets_fail_before_any_tree_or_scope_change(self) -> None:
        def prepare(root: Path) -> None:
            vpn = root / "bin/vpn"
            vpn.chmod(0o777)
        fixture = make_deployed_workspace("manual", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        try:
            vpn = root / "bin/vpn"
            family = root / "evidence/immersive"
            family.mkdir(parents=True)
            (root / "evidence").chmod(0o777)
            family.chmod(0o777)

            symlink_target = family / "linked-source"
            symlink_target.symlink_to(root / "bin", target_is_directory=True)
            special_target = family / "special-target"
            os.mkfifo(special_target, mode=0o666)
            existing_target = family / "existing-target"
            existing_target.mkdir(mode=0o777)
            sentinel = existing_target / "sentinel.bin"
            sentinel.write_bytes(b"must stay byte-and-mode identical")
            sentinel.chmod(0o666)

            namespace, globals_dict = self.load_capture(root)
            read_env = mock.Mock(side_effect=AssertionError("environment read occurred"))
            network = mock.Mock(side_effect=AssertionError("network policy occurred"))
            scope = mock.Mock(side_effect=AssertionError("scope check occurred"))
            globals_dict["read_env"] = read_env
            globals_dict["resolve_network_policy"] = network
            globals_dict["scope_guard_url"] = scope
            before = snapshot_tree(root)
            invalid_targets = (
                ".",
                str(root),
                str(root / "bin"),
                str(symlink_target),
                str(special_target),
                str(existing_target),
            )

            for outdir in invalid_targets:
                with self.subTest(outdir=outdir), mock.patch.object(
                    sys,
                    "argv",
                    [
                        "immersive-cluster-capture",
                        "--url",
                        "wss://fixture.invalid/cable",
                        "--outdir",
                        outdir,
                    ],
                ):
                    self.assertEqual(namespace["main"](), 2)
                    self.assertEqual(snapshot_tree(root), before)

            read_env.assert_not_called()
            network.assert_not_called()
            scope.assert_not_called()
            self.assertEqual(stat.S_IMODE(vpn.stat().st_mode), 0o777)
        finally:
            fixture.cleanup()

    def test_scope_refusal_preserves_source_without_creating_output(self) -> None:
        def prepare(root: Path) -> None:
            vpn = root / "bin/vpn"
            vpn.chmod(0o777)
        fixture = make_deployed_workspace("manual", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        try:
            vpn = root / "bin/vpn"
            before = snapshot_tree(root)
            outdir = root / "evidence/immersive/fresh-capture"
            namespace, globals_dict = self.load_capture(root)
            scope = mock.Mock(side_effect=RuntimeError("fixture scope denial"))
            globals_dict["read_env"] = lambda: {}
            network = types.SimpleNamespace()
            network.environment = object()
            network.from_child_environment = lambda _environment, *, scope: network
            network.websocket_options = lambda _url: {}
            network.metadata = lambda: {}
            globals_dict["resolve_network_policy"] = lambda *_args: network
            globals_dict["scope_guard_url"] = scope

            with mock.patch.object(
                sys,
                "argv",
                [
                    "immersive-cluster-capture",
                    "--url",
                    "wss://fixture.invalid/cable",
                    "--outdir",
                    str(outdir),
                ],
            ):
                self.assertEqual(namespace["main"](), 4)

            after = snapshot_tree(root)
            for relative, identity in before.items():
                self.assertEqual(after[relative], identity, relative)
            self.assertEqual(stat.S_IMODE(vpn.stat().st_mode), 0o777)
            self.assertFalse(outdir.exists())
            scope.assert_called_once_with("wss://fixture.invalid/cable")
        finally:
            fixture.cleanup()

    def test_offscope_declared_proxy_fails_before_output_or_websocket(self) -> None:
        def prepare(root: Path) -> None:
            replace_env_assignments(
                root,
                {
                    "ADAPTER_CONFIG_INVENTORY_ARGV": '["/usr/bin/printf","{}"]',
                    "ADAPTER_CONFIG_SUBMIT_ARGV": '["true"]',
                    "IMMERSIVE_COOKIES_FILE": "/private/cookies.json",
                    "IMMERSIVE_NETWORK_ENV_KEYS": '["HTTPS_PROXY"]',
                    "HTTPS_PROXY": "http://proxy.invalid:8080",
                },
            )
        fixture = make_deployed_workspace("immersive", prepare=prepare)
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name)
        try:
            outdir = root / "evidence/immersive/offscope-proxy"
            namespace, globals_dict = self.load_capture(root)
            globals_dict["scope_guard_url"] = mock.Mock(
                return_value=fake_binding(scoped())
            )
            globals_dict["_verify_effect_binding"] = lambda binding: binding
            globals_dict["_scope_effect"] = lambda binding: nullcontext(binding)
            fake_websocket = types.SimpleNamespace(create_connection=mock.Mock())

            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "immersive-cluster-capture",
                        "--url",
                        "wss://fixture.invalid/cable",
                        "--outdir",
                        str(outdir),
                    ],
                ),
                mock.patch.dict(sys.modules, {"websocket": fake_websocket}),
            ):
                self.assertEqual(namespace["main"](), 2)

            self.assertFalse(outdir.exists())
            fake_websocket.create_connection.assert_not_called()
        finally:
            fixture.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
