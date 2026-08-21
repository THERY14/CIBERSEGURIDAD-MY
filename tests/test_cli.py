from pathlib import Path

from cyberlabkit.cli import init_lab, report


def test_init_and_report(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert init_lab("demo") == 0
    assert (tmp_path / "demo" / "lab.yaml").exists()
    assert (tmp_path / "demo" / "evidence").is_dir()
    assert (tmp_path / "demo" / "notes").is_dir()
    assert report("demo") == 0
    report_text = (tmp_path / "demo" / "REPORT.md").read_text(encoding="utf-8")
    assert "CyberLabKit Lab Report" in report_text
