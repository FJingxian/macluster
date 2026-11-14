import pathlib
import shutil
import sys
import tempfile
import unittest


RELEASE_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELEASE_DIR))

from sign_macos import (
    SigningError,
    codesign_command,
    extract_designated_requirement,
    is_distribution_identity,
    require_stable_requirement,
    sign_binary,
    select_signing_identity,
)


class SignMacosTests(unittest.TestCase):
    def test_prefers_developer_id_then_development_identity(self):
        identities = [
            "Apple Development: user@example.com (TEAM)",
            "Developer ID Application: Example Lab (TEAM)",
        ]

        self.assertEqual(
            select_signing_identity(identities),
            "Developer ID Application: Example Lab (TEAM)",
        )
        self.assertEqual(
            select_signing_identity(identities[:1]),
            "Apple Development: user@example.com (TEAM)",
        )
        self.assertTrue(
            is_distribution_identity(
                "Developer ID Application: Example Lab (TEAM)"
            )
        )
        self.assertFalse(
            is_distribution_identity(
                "Apple Development: user@example.com (TEAM)"
            )
        )

    def test_requested_identity_and_distribution_only_mode_are_enforced(self):
        identities = [
            "Apple Development: user@example.com (TEAM)",
            "Developer ID Application: Example Lab (TEAM)",
        ]

        self.assertEqual(
            select_signing_identity(
                identities,
                requested="Apple Development: user@example.com (TEAM)",
            ),
            "Apple Development: user@example.com (TEAM)",
        )
        self.assertEqual(
            select_signing_identity(identities, distribution_only=True),
            "Developer ID Application: Example Lab (TEAM)",
        )
        with self.assertRaisesRegex(SigningError, "Developer ID Application"):
            select_signing_identity(identities[:1], distribution_only=True)

    def test_codesign_command_uses_stable_identifier_and_hardened_runtime(self):
        command = codesign_command(
            pathlib.Path("/tmp/macluster"),
            "Apple Development: user@example.com (TEAM)",
            timestamp=True,
        )

        self.assertEqual(command[0], "codesign")
        self.assertIn("--force", command)
        self.assertIn("--timestamp", command)
        self.assertIn("--options", command)
        self.assertIn("runtime", command)
        self.assertIn("org.macluster.macluster", command)
        self.assertEqual(command[-1], "/tmp/macluster")

    def test_cdhash_requirement_is_not_stable(self):
        stable = (
            'designated => identifier "org.macluster.macluster" and '
            "anchor apple generic and certificate leaf[subject.OU] = TEAM"
        )
        require_stable_requirement(stable)

        with self.assertRaisesRegex(SigningError, "CDHash"):
            require_stable_requirement(
                'designated => cdhash H"a287afc4dc8da6993b711f281b1fe2a23b48a73c"'
            )

    def test_designated_requirement_is_read_from_stdout(self):
        requirement = (
            'designated => identifier "org.macluster.macluster" and '
            "anchor apple generic"
        )

        self.assertEqual(
            extract_designated_requirement(
                requirement + "\n",
                "Executable=/tmp/macluster\n",
            ),
            requirement,
        )

    def test_explicit_adhoc_signing_does_not_require_a_stable_requirement(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = pathlib.Path(temporary) / "true"
            shutil.copyfile("/usr/bin/true", binary)
            binary.chmod(0o755)

            self.assertEqual(
                sign_binary(binary, "-", timestamp=False),
                "",
            )


if __name__ == "__main__":
    unittest.main()
