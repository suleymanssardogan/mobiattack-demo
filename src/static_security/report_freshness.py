"""Bind Static reports to the evaluator revision and explicit run; never re-evaluate history."""
import hashlib
import json
from pathlib import Path


def evaluation_revision():
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for relative in ('vulnerability_evaluator.py', 'static_security/catalog.py', 'static_security/false_positive.py'):
        digest.update(relative.encode())
        digest.update((root / relative).read_bytes())
    return digest.hexdigest()


# Snapshot at import: an old running process cannot label its old evaluator as new.
STATIC_EVALUATION_REVISION = evaluation_revision()


def load_current_static_report(directory, run_id):
    report = json.loads((Path(directory) / 'static_analysis_report.json').read_text())
    if (not isinstance(report, dict) or report.get('report_type') != 'static_analysis'
            or report.get('run_id') != run_id
            or report.get('static_evaluation_revision') != evaluation_revision()):
        raise ValueError('Static report is historical or mismatched; run a fresh Static scan.')
    return report
