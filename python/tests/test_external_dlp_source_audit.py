import hashlib
import json
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from patronus_ark import external_dlp_eval


DATA_DIR = Path(__file__).resolve().parents[1] / "patronus_ark" / "benchmark_data" / "external_dlp"


class ExternalDlpSourceAuditTests(unittest.TestCase):
    def test_manifest_admits_only_the_permissive_gitleaks_content_source(self):
        manifest = json.loads((DATA_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "ark-external-dlp-manifest-v1")
        corpora = manifest["corpora"]
        self.assertEqual([entry["id"] for entry in corpora], ["gitleaks-go-source-v8", "schemapile-perm-sql-v1"])
        gitleaks, schemapile = corpora
        self.assertEqual(gitleaks["admission_status"], "admitted")
        self.assertEqual(gitleaks["license"], "MIT")
        self.assertEqual(gitleaks["positive"]["expected_documents"], 214)
        self.assertEqual(schemapile["admission_status"], "admitted")
        self.assertEqual(schemapile["positive"]["target_cap"], 250)
        self.assertEqual(len(schemapile["verified_sha256"]), 64)
        self.assertNotIn("ProwlBench", json.dumps(corpora))

    def test_git_tree_adapter_validates_revision_license_and_document_labels(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "LICENSE").write_text("MIT fixture\n", encoding="utf-8")
            (root / "main.go").write_text("package main\n", encoding="utf-8")
            (root / "README.md").write_text("documentation\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(root), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
                check=True,
            )
            revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            manifest = {"corpora": [{
                "id": "fixture", "admission_status": "admitted", "adapter": "git_tree_content_v1",
                "revision": revision,
                "license_file_sha256": hashlib.sha256((root / "LICENSE").read_bytes()).hexdigest(),
                "positive": {"entity_type": "dlp.content.source_code", "extensions": [".go"], "expected_documents": 1},
                "negative": {"extensions": [".md"], "expected_minimum_documents": 1},
            }]}
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            rows = external_dlp_eval.normalize_git_tree(root, "fixture", manifest_path)
        by_path = {row["source_path"]: row for row in rows}
        self.assertEqual(by_path["main.go"]["document_label"], "dlp.content.source_code")
        self.assertIsNone(by_path["README.md"]["document_label"])

    def test_sql_archive_adapter_keeps_exact_statement_offsets(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "sql.tar.gz"
            source_path = root / "sample.sql"
            source_text = "-- comment;\nCREATE TABLE t (v text);\nINSERT INTO t VALUES ('semi;colon');\n"
            source_path.write_text(source_text, encoding="utf-8")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(source_path, arcname="sqlfiles_permissive/sample.sql")
            manifest = {"corpora": [{
                "id": "fixture", "admission_status": "admitted", "adapter": "tar_sql_statement_v1",
                "verified_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                "positive": {"entity_type": "dlp.content.sql", "target_cap": 2},
            }]}
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            rows = external_dlp_eval.normalize_sql_archive(archive_path, "fixture", manifest_path)
        self.assertEqual([row["text"][row["entities"][0]["start"]:row["entities"][0]["end"]] for row in rows], [
            "-- comment;\nCREATE TABLE t (v text);",
            "INSERT INTO t VALUES ('semi;colon');",
        ])


if __name__ == "__main__":
    unittest.main()
