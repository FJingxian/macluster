import hashlib
import pathlib
import sys
import tarfile
import tempfile
import unittest


RELEASE_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELEASE_DIR))

from package_macos import PackageError, package_release


class PackageMacosTests(unittest.TestCase):
    def test_packages_only_the_clean_executable_and_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            binary = root / "macluster"
            binary.write_bytes(b"signed-binary")
            binary.chmod(0o755)
            output = root / "output"

            asset, digest = package_release(binary, "0.1.7", output)

            self.assertEqual(asset.name, "macluster-v0.1.7-macos-arm64.tar.gz")
            self.assertEqual(
                digest,
                hashlib.sha256(asset.read_bytes()).hexdigest(),
            )
            with tarfile.open(asset, "r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual([member.name for member in members], ["macluster"])
                self.assertEqual(members[0].mode, 0o755)
                self.assertEqual(
                    archive.extractfile("macluster").read(),
                    b"signed-binary",
                )
            self.assertEqual(
                (output / "SHA256SUMS").read_text(),
                f"{digest}  {asset.name}\n",
            )

    def test_rejects_missing_or_unsafe_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            binary = root / "macluster"
            binary.write_bytes(b"binary")
            with self.assertRaises(PackageError):
                package_release(root / "missing", "0.1.7", root / "output")
            with self.assertRaises(PackageError):
                package_release(binary, "../0.1.7", root / "output")


if __name__ == "__main__":
    unittest.main()
