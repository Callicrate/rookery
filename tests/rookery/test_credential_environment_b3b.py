from __future__ import annotations

# ruff: noqa: E402

import io
import json
import os
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.rookery.support import ROOKERY_ROOT
from tests.rookery.test_preparation_and_isolation import copy_rookery

LIB = ROOKERY_ROOT / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from rookery.portable.adapters import BoundedCommandResult
from rookery.portable.environment import EnvironmentPolicyError
from rookery.portable.store import EventStore


SENTINELS = {
    "CTFD_TOKEN": "b3b-ctfd-secret",
    "HTTP_PROXY": "http://b3b-proxy.invalid",
    "ROOKERY_OWNER_TOKEN": "b3b-owner-token",
    "DUMMY_HEALTH": "b3b-health-grant",
    "DUMMY_NEAR_MISS": "b3b-near-miss-grant",
    "DUMMY_CLEANUP": "b3b-cleanup-grant",
}


class ScriptGlobals:
    """Attribute-friendly access to the real global dictionary of a script."""

    def __init__(self, values: dict[str, object]) -> None:
        object.__setattr__(self, "values", values)

    def __getattr__(self, name: str):
        try:
            return self.values[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: object) -> None:
        self.values[name] = value

    def __delattr__(self, name: str) -> None:
        del self.values[name]


def load_script(root: Path, name: str) -> ScriptGlobals:
    namespace = runpy.run_path(str(root / "bin" / name), run_name=f"b3b_{name}")
    values = namespace["main"].__globals__
    values["ROOT"] = root
    return ScriptGlobals(values)


def bounded(environment) -> BoundedCommandResult:
    return BoundedCommandResult(
        returncode=0,
        stdout=b"",
        stderr=b"",
        termination="exited",
        environment=environment.metadata()["environment"],
    )


@unittest.skipUnless(os.name == "posix", "requires Linux/WSL private-mode support")
class CredentialEnvironmentB3bTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        copy_rookery(self.root)
        # These direct helper tests are intentionally non-deployed unit roots.
        # They never install a synthetic binding or exercise public admission.
        (self.root / "VERSION").unlink()
        (self.root / "bin" / "rookery").unlink()
        EventStore(self.root).rebuild()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_credential_health_grants_only_declared_probe_names(self) -> None:
        module = load_script(self.root, "credential-health")
        (self.root / ".env").write_text(
            "CREDENTIAL_HEALTH_ARGV=[\"health-probe\"]\n"
            "CREDENTIAL_HEALTH_ENV_KEYS=[\"DUMMY_HEALTH\"]\n"
            "DUMMY_HEALTH=dotenv-health-grant\n"
            "CTFD_TOKEN=dotenv-ctfd-secret\n",
            encoding="utf-8",
        )
        args = SimpleNamespace(
            argv_json="",
            command="",
            max_age_minutes=None,
            max_output_bytes=1024,
            file=[],
        )
        with mock.patch.dict(os.environ, SENTINELS, clear=False):
            _values, argv, child, _age, _timeout, _files = module.health_configuration(args)
        self.assertEqual(argv, ["health-probe"])
        self.assertIsNotNone(child)
        assert child is not None
        self.assertEqual(child.values["DUMMY_HEALTH"], "dotenv-health-grant")
        self.assertFalse({"CTFD_TOKEN", "HTTP_PROXY", "ROOKERY_OWNER_TOKEN"} & set(child.values))
        self.assertNotIn("dotenv-health-grant", json.dumps(child.metadata()))

    def test_near_miss_configuration_is_validated_before_artifacts(self) -> None:
        module = load_script(self.root, "near-miss-retry")
        (self.root / ".env").write_text(
            "NEAR_MISS_PROBE_ARGV=not-json\n"
            "DUMMY_NEAR_MISS=dotenv-near-miss-grant\n",
            encoding="utf-8",
        )
        argv = [
            "near-miss-retry",
            "challenge",
            "candidate",
            "--run",
        ]
        near_miss_root = self.root / "analysis" / "near-miss"
        before = set(near_miss_root.glob("*")) if near_miss_root.is_dir() else set()
        with mock.patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(), 2)
        after = set(near_miss_root.glob("*")) if near_miss_root.is_dir() else set()
        self.assertEqual(after, before)
        self.assertFalse((self.root / "state" / "near_misses.jsonl").exists())

    def test_near_miss_probe_environment_is_exact_and_value_free(self) -> None:
        module = load_script(self.root, "near-miss-retry")
        (self.root / ".env").write_text(
            "NEAR_MISS_PROBE_ARGV=[\"probe\",\"{candidate}\"]\n"
            "NEAR_MISS_PROBE_ENV_KEYS=[\"DUMMY_NEAR_MISS\"]\n"
            "DUMMY_NEAR_MISS=dotenv-near-miss-grant\n",
            encoding="utf-8",
        )
        args = SimpleNamespace(
            probe_timeout=10,
            max_output_bytes=1024,
            probe_command="",
            probe_argv_json="",
            run=True,
            challenge="fixture",
            candidate="candidate",
        )
        probes = [{"idx": 1, "prompt": "fixture", "value": "candidate"}]
        with mock.patch.dict(os.environ, SENTINELS, clear=False):
            child, rendered, _template = module._probe_configuration(args, probes)
        self.assertEqual(rendered, (["probe", "candidate"],))
        self.assertIsNotNone(child)
        assert child is not None
        self.assertEqual(child.values["DUMMY_NEAR_MISS"], "dotenv-near-miss-grant")
        self.assertFalse({"CTFD_TOKEN", "HTTP_PROXY", "ROOKERY_OWNER_TOKEN"} & set(child.values))
        self.assertNotIn("dotenv-near-miss-grant", json.dumps(child.metadata()))

    def test_cleanup_persists_names_and_old_records_execute_minimally(self) -> None:
        module = load_script(self.root, "rookery-ops")
        (self.root / ".env").write_text(
            "DUMMY_CLEANUP=dotenv-cleanup-grant\n", encoding="utf-8"
        )
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "rookery-ops",
                    "cleanup",
                    "register",
                    "--label",
                    "fixture",
                    "--argv-json",
                    '["cleanup"]',
                    "--pass-env",
                    "DUMMY_CLEANUP",
                ],
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(module.main(), 0)
        rows = [
            json.loads(line)
            for line in (self.root / "state" / "cleanup_hooks.jsonl").read_text().splitlines()
        ]
        self.assertEqual(rows[0]["pass_env"], ["DUMMY_CLEANUP"])
        self.assertNotIn("dotenv-cleanup-grant", json.dumps(rows[0]))

        old = {
            "cleanup_id": "legacy",
            "label": "legacy",
            "command_argv": ["cleanup"],
            "status": "registered",
        }
        with (self.root / "state" / "cleanup_hooks.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(old) + "\n")
        observed = []
        with (
            mock.patch.dict(os.environ, SENTINELS, clear=False),
            mock.patch.object(module, "run_bounded_argv") as launched,
            mock.patch.object(sys, "argv", ["rookery-ops", "cleanup", "run", "--id", "legacy"]),
            redirect_stdout(io.StringIO()),
        ):
            launched.side_effect = lambda *_args, **kwargs: (
                observed.append(kwargs["env"]) or bounded(kwargs["env"])
            )
            self.assertEqual(module.main(), 0)
        self.assertEqual(len(observed), 1)
        self.assertFalse(set(SENTINELS) & set(observed[0].values))
        self.assertNotIn(SENTINELS["DUMMY_CLEANUP"], json.dumps(observed[0].metadata()))

    def test_transit_transport_uses_dns_pinned_transport_with_no_ambient_network_grant(self) -> None:
        module = load_script(self.root, "transit-source")
        (self.root / ".env").write_text(
            "TRANSIT_SOURCE_NETWORK_ENV_KEYS=[]\n", encoding="utf-8"
        )
        scope = {
            "acknowledged": True,
            "generation": 1,
            "expires_at": "unknown",
            "allowed_hosts": ["fixture.invalid"],
            "allowed_cidrs": [],
            "allowed_ports": [443],
            "allowed_protocols": ["https"],
            "allowed_file_origins": [],
            "platform_hosts": [],
            "max_attachment_bytes": 1024,
        }
        with mock.patch.dict(os.environ, SENTINELS, clear=False):
            policy = module.transit_network_policy(scope)
        transport = policy.scoped_transport(scope)
        metadata = policy.metadata()
        self.assertNotIn(SENTINELS["HTTP_PROXY"], json.dumps(metadata))
        self.assertTrue(callable(getattr(transport, "preflight_url", None)))
        self.assertTrue(callable(getattr(transport, "open", None)))

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b"GTFS"

        destination = mock.Mock()
        with mock.patch.object(module, "open_scoped_url", return_value=Response()) as opened:
            module.download_feed(
                "https://fixture.invalid/feed.zip",
                destination,
                32,
                scope={"acknowledged": True},
                transport=transport,
                binding=None,
            )
        destination.write_bytes.assert_called_once_with("feed.zip", b"GTFS", binding=None)
        self.assertEqual(opened.call_args.args[1], "https://fixture.invalid/feed.zip")
        self.assertTrue(opened.call_args.kwargs["attachment"])
        self.assertIs(opened.call_args.kwargs["transport"], transport)

    def test_auth_scope_child_is_minimal(self) -> None:
        auth = load_script(self.root, "auth-expired-stop")
        observed = []

        def capture(*_args, **kwargs):
            observed.append(kwargs["env"])
            return bounded(kwargs["env"])

        with (
            mock.patch.dict(os.environ, SENTINELS, clear=False),
            mock.patch.object(auth, "run_bounded_argv", side_effect=capture),
        ):
            self.assertEqual(auth.run(["status"], 1, 1024).termination, "exited")
        self.assertEqual([child.policy_name for child in observed], ["auth-expired-stop"])
        for child in observed:
            self.assertFalse(set(SENTINELS) & set(child.values))
            self.assertNotIn(SENTINELS["CTFD_TOKEN"], json.dumps(child.metadata()))

    def test_transit_invalid_ca_fails_before_a_transport_is_created(self) -> None:
        module = load_script(self.root, "transit-source")
        missing_ca = self.root / "missing-ca.pem"
        (self.root / ".env").write_text(
            "TRANSIT_SOURCE_NETWORK_ENV_KEYS=[\"SSL_CERT_FILE\"]\n"
            f"SSL_CERT_FILE={missing_ca}\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(module.ExplicitNetworkPolicy, "from_child_environment") as policy,
            self.assertRaises(EnvironmentPolicyError),
        ):
            module.transit_network_policy({"acknowledged": True})
        policy.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
