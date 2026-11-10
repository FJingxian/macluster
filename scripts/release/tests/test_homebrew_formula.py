import pathlib
import sys
import unittest


RELEASE_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RELEASE_DIR))

from homebrew_formula import FormulaError, render_formula


class HomebrewFormulaTests(unittest.TestCase):
    def test_renders_a_release_linked_arm64_formula(self):
        digest = "a" * 64
        formula = render_formula("0.1.7", digest)

        self.assertNotIn('version "0.1.7"', formula)
        self.assertIn(
            "https://github.com/FJingxian/macluster/releases/download/"
            "v0.1.7/macluster-v0.1.7-macos-arm64.tar.gz",
            formula,
        )
        self.assertIn(f'sha256 "{digest}"', formula)
        self.assertIn("depends_on arch: :arm64", formula)
        self.assertIn('depends_on macos: ">= :monterey"', formula)
        self.assertIn('bin.install "macluster"', formula)
        self.assertIn(
            "aliases = %w[msub mjob mqueue mkill mtop mnode mfans]",
            formula,
        )
        self.assertIn('bin.install_symlink bin/"macluster" => name', formula)
        self.assertIn('assert_match version.to_s', formula)
        self.assertTrue(formula.startswith("# typed: strict\n"))
        self.assertIn("livecheck do", formula)
        self.assertIn("strategy :github_latest", formula)
        self.assertLess(formula.index("livecheck do"), formula.index("depends_on"))

    def test_rejects_unsafe_versions_and_digests(self):
        with self.assertRaises(FormulaError):
            render_formula("0.1.7; rm -rf /", "a" * 64)
        with self.assertRaises(FormulaError):
            render_formula("0.1.7", "not-a-sha256")


if __name__ == "__main__":
    unittest.main()
