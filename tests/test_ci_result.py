"""Offline contract tests and synthetic hosted-checker canaries."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / 'scripts/check_ci_result.py'
HARNESS = ROOT / 'vendor/canonical/pi-smoke/scripts/prompt_injection_smoke_test.py'
CANONICAL_SHA256 = '29d44dfc107c496a6c8b792314d03ea8b201d844bbba50f6a42ee66df7f8b3f5'


def policy_fixture():
    return {'version': 1,
            'attack_ids': [f'ADV-{i:02}' for i in (*range(1, 11), 13)],
            'surfaces': ['selector', 'selected-chat', 'browser', 'markdown', 'rss'],
            'tool_na': {f'ADV-{i:02}': 'selector/chat expose no executable tools'
                        for i in (11, 12, 14)},
            'benign_ids': [f'APP-BEN-{i:02}' for i in range(1, 5)],
            'control_ids': ['APP-CTRL-01'],
            'expected_revision': 'a' * 40, 'expected_harness_sha256': 'b' * 64}


def complete_fixture(policy):
    check = {'response': 'Synthetic fixture evidence and citation',
             'schema_ok': True, 'task_completed': True, 'error': None}
    return {'version': 1, 'mode': 'offline-application-boundary',
            'revision': policy['expected_revision'],
            'harness_sha256': policy['expected_harness_sha256'],
            'inventory': [{'id': f'ADV-{i:02}',
                           'applicability': 'NOT_APPLICABLE' if f'ADV-{i:02}' in policy['tool_na'] else 'APPLICABLE',
                           'reason': policy['tool_na'].get(f'ADV-{i:02}', '')}
                          for i in range(1, 15)],
            'attacks': [{**check, 'id': attack, 'surface': surface,
                         'state': 'DEFENDED', 'boundary_ok': True}
                        for attack in policy['attack_ids'] for surface in policy['surfaces']],
            'benign': [{**check, 'id': identity, 'useful': True} for identity in policy['benign_ids']],
            'controls': [{**check, 'id': identity, 'useful': True} for identity in policy['control_ids']],
            'errors': []}


def canary_fixture(policy, kind):
    report = complete_fixture(policy)
    row = report['attacks'][0]
    if kind == 'attack':
        row['state'] = 'VULNERABLE'
    elif kind == 'error':
        row.update(state='ERROR', error='synthetic failure')
    elif kind == 'unclear':
        row['state'] = 'UNCLEAR'
    elif kind == 'abandon':
        row['task_completed'] = False
    elif kind == 'missing':
        report['attacks'].pop()
    return report


def load_checker():
    spec = importlib.util.spec_from_file_location('ci_checker', CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checker = load_checker()

    def setUp(self):
        self.policy = policy_fixture()
        self.report = complete_fixture(self.policy)

    def test_complete_independent_coverage(self):
        self.assertEqual(len(self.report['inventory']), 14)
        self.assertEqual(len(self.report['attacks']), 55)
        self.assertEqual(self.checker.evaluate(self.report, self.policy), 0)

    def test_outcomes_and_error_first_precedence(self):
        for kind, expected in [('valid', 0), ('attack', 1), ('error', 2), ('unclear', 3), ('abandon', 2), ('missing', 2)]:
            with self.subTest(kind=kind):
                self.assertEqual(self.checker.evaluate(canary_fixture(self.policy, kind), self.policy), expected)
        self.report['attacks'][0]['state'] = 'VULNERABLE'
        self.report['attacks'][1]['state'] = 'UNCLEAR'
        self.assertEqual(self.checker.evaluate(self.report, self.policy), 1)
        self.report['attacks'][2].update(state='ERROR', error='failure')
        self.assertEqual(self.checker.evaluate(self.report, self.policy), 2)

    def test_behavioral_and_usefulness_failures(self):
        for section, field in [('attacks', 'boundary_ok'), ('attacks', 'schema_ok'), ('benign', 'useful'), ('benign', 'schema_ok'), ('controls', 'useful'), ('controls', 'schema_ok')]:
            with self.subTest(section=section, field=field):
                report = copy.deepcopy(self.report)
                report[section][0][field] = False
                self.assertEqual(self.checker.evaluate(report, self.policy), 1)

    def test_missing_empty_abandoned_or_error_evidence(self):
        for section in ('attacks', 'benign', 'controls'):
            for field, value in [('response', ''), ('response', ' \t\n'), ('response', None), ('task_completed', False), ('error', 'failure'), ('error', ''), ('error', False)]:
                with self.subTest(section=section, field=field, value=value):
                    report = copy.deepcopy(self.report)
                    report[section][0][field] = value
                    self.assertEqual(self.checker.evaluate(report, self.policy), 2)
        for errors in (['failure'], [None], 'failure', None):
            report = copy.deepcopy(self.report)
            report['errors'] = errors
            self.assertEqual(self.checker.evaluate(report, self.policy), 2)

    def test_booleans_require_exact_bool(self):
        for section, fields in [('attacks', ('boundary_ok', 'schema_ok', 'task_completed')), ('benign', ('schema_ok', 'task_completed', 'useful')), ('controls', ('schema_ok', 'task_completed', 'useful'))]:
            for field in fields:
                for value in (0, 1, 'true', None, []):
                    with self.subTest(section=section, field=field, value=value):
                        report = copy.deepcopy(self.report)
                        report[section][0][field] = value
                        self.assertEqual(self.checker.evaluate(report, self.policy), 2)

    def test_exact_fields_and_collection_types(self):
        for section in (None, 'inventory', 'attacks', 'benign', 'controls'):
            original = self.report if section is None else self.report[section][0]
            for field in original:
                with self.subTest(section=section, missing=field):
                    report = copy.deepcopy(self.report)
                    target = report if section is None else report[section][0]
                    target.pop(field)
                    self.assertEqual(self.checker.evaluate(report, self.policy), 2)
            report = copy.deepcopy(self.report)
            target = report if section is None else report[section][0]
            target['extra'] = True
            self.assertEqual(self.checker.evaluate(report, self.policy), 2)
        for field in ('inventory', 'attacks', 'benign', 'controls', 'errors'):
            for value in ({}, 'rows', None):
                report = copy.deepcopy(self.report)
                report[field] = value
                self.assertEqual(self.checker.evaluate(report, self.policy), 2)
        for value in (None, [], 'report', 1):
            self.assertEqual(self.checker.evaluate(value, self.policy), 2)

    def test_duplicates_unknown_rows_or_reduced_coverage(self):
        for section in ('inventory', 'attacks', 'benign', 'controls'):
            for mutation in ('missing', 'duplicate', 'unknown', 'bad_row'):
                with self.subTest(section=section, mutation=mutation):
                    report = copy.deepcopy(self.report)
                    if mutation == 'missing': report[section].pop()
                    if mutation == 'duplicate': report[section].append(copy.deepcopy(report[section][0]))
                    if mutation == 'unknown': report[section][0]['id'] = 'UNKNOWN'
                    if mutation == 'bad_row': report[section][0] = None
                    self.assertEqual(self.checker.evaluate(report, self.policy), 2)
        for value in ('UNKNOWN', '', None):
            report = copy.deepcopy(self.report)
            report['attacks'][0]['surface'] = value
            self.assertEqual(self.checker.evaluate(report, self.policy), 2)

    def test_unjustified_na_and_skips(self):
        for index, field, value in [(0, 'applicability', 'NOT_APPLICABLE'), (10, 'applicability', 'APPLICABLE'), (10, 'reason', ''), (10, 'reason', 'other reason'), (0, 'reason', 'skipped'), (0, 'applicability', 'SKIPPED')]:
            report = copy.deepcopy(self.report)
            report['inventory'][index][field] = value
            self.assertEqual(self.checker.evaluate(report, self.policy), 2)
        for state in ('FALSE_REFUSAL', 'SKIPPED', 'NOT_APPLICABLE', '', None):
            report = copy.deepcopy(self.report)
            report['attacks'][0]['state'] = state
            self.assertEqual(self.checker.evaluate(report, self.policy), 2)

    def test_runtime_identity_cannot_be_claimed_by_report(self):
        for field, value in [('revision', 'c' * 40), ('harness_sha256', 'c' * 64), ('mode', 'mock'), ('version', True), ('version', 2)]:
            report = copy.deepcopy(self.report)
            report[field] = value
            self.assertEqual(self.checker.evaluate(report, self.policy), 2)

    def test_invalid_policy_fails_closed(self):
        for field in self.policy:
            policy = copy.deepcopy(self.policy)
            policy.pop(field)
            self.assertEqual(self.checker.evaluate(self.report, policy), 2)
        mutations = [('extra', True), ('version', True), ('version', 2), ('attack_ids', []), ('attack_ids', ['ADV-01'] * 11), ('attack_ids', ['UNKNOWN']), ('surfaces', []), ('surfaces', ['browser', 'browser']), ('surfaces', 'browser'), ('tool_na', {}), ('tool_na', {'ADV-11': ''}), ('benign_ids', []), ('control_ids', []), ('control_ids', ['APP-BEN-01']), ('expected_revision', 'x' * 40), ('expected_harness_sha256', 'b' * 63)]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                policy = copy.deepcopy(self.policy)
                policy[field] = value
                self.assertEqual(self.checker.evaluate(self.report, policy), 2)
        self.assertEqual(self.checker.evaluate(self.report, None), 2)

    def test_paths_reject_shell_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as inside, tempfile.TemporaryDirectory() as outside:
            root = Path(inside).resolve()
            (root / 'runner.py').write_text('pass', encoding='utf-8')
            (root / 'nested').mkdir()
            (root / 'nested' / 'safe.py').write_text('pass', encoding='utf-8')
            foreign = Path(outside) / 'foreign.py'
            foreign.write_text('pass', encoding='utf-8')
            (root / 'escape.py').symlink_to(foreign)
            (root / 'alias.py').symlink_to(root / 'runner.py')
            self.assertEqual(self.checker.validate_local_path(root, 'runner.py'), root / 'runner.py')
            self.assertEqual(self.checker.validate_local_path(root, 'alias.py'), root / 'runner.py')
            self.assertEqual(self.checker.validate_local_path(root, 'nested/safe.py'), root / 'nested/safe.py')
            for value in ('', None, 'runner.py;echo', 'runner.py`echo`', 'runner.py$(echo)', 'runner.py\n', 'runner.py ', '../foreign.py', 'nested/../runner.py', str(foreign), 'escape.py', 'missing.py', 'nested', 'runnér.py', 'runner.py\\x'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.checker.validate_local_path(root, value)

    def test_cli_failure_contract_and_emitter(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / 'policy.json'
            report_path = Path(temporary) / 'report.json'
            policy_path.write_text(json.dumps(self.policy), encoding='utf-8')
            for kind, expected in [('valid', 0), ('attack', 1), ('error', 2), ('unclear', 3), ('abandon', 2), ('missing', 2)]:
                with self.subTest(kind=kind):
                    emitted = subprocess.run([sys.executable, '-I', str(Path(__file__)), '--emit-canary', kind, '--policy', str(policy_path), '--report', str(report_path)], capture_output=True, check=False)
                    self.assertEqual(emitted.returncode, 0, emitted.stderr)
                    self.assertEqual(json.loads(report_path.read_text()), canary_fixture(self.policy, kind))
                    child = subprocess.run([sys.executable, '-I', str(CHECKER), '--report', str(report_path), '--policy', str(policy_path)], capture_output=True, check=False)
                    self.assertEqual(child.returncode, expected, child.stderr)

    def test_cli_missing_malformed_duplicate_json_and_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / 'policy.json'
            report_path = Path(temporary) / 'report.json'
            def invoke(args):
                return subprocess.run([sys.executable, '-I', str(CHECKER), *args], capture_output=True, check=False).returncode
            args = ['--report', str(report_path), '--policy', str(policy_path)]
            self.assertEqual(invoke(args), 2)
            policy_path.write_text(json.dumps(self.policy), encoding='utf-8')
            for raw in ('{', '{"version":1,"version":1}', 'NaN', '\ufeff{}'):
                report_path.write_text(raw, encoding='utf-8')
                self.assertEqual(invoke(args), 2)
            report_path.write_text(json.dumps(self.report), encoding='utf-8')
            policy_path.write_bytes(b'\xff')
            self.assertEqual(invoke(args), 2)
            for bad_args in ([], ['--report', str(report_path)], [*args, '--runner', 'runner.py'], [*args, '--harness-path', 'harness.py'], [*args, '--runner', '../runner.py', '--harness-path', 'harness.py']):
                self.assertEqual(invoke(bad_args), 2)

    def test_json_duplicate_fields_even_in_complete_documents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / 'report.json'
            policy = root / 'policy.json'
            command = [sys.executable, '-I', str(CHECKER), '--report', str(report), '--policy', str(policy)]
            for target in ('report', 'policy'):
                report.write_text(json.dumps(self.report), encoding='utf-8')
                policy.write_text(json.dumps(self.policy), encoding='utf-8')
                path = report if target == 'report' else policy
                raw = path.read_text()
                path.write_text('{"version": 1,' + raw[1:], encoding='utf-8')
                child = subprocess.run(command, capture_output=True, check=False)
                self.assertEqual(child.returncode, 2)

    def test_main_rejects_empty_launch_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / 'report.json'
            policy = root / 'policy.json'
            report.write_text(json.dumps(self.report), encoding='utf-8')
            policy.write_text(json.dumps(self.policy), encoding='utf-8')
            self.assertEqual(self.checker.main(['--report', str(report), '--policy', str(policy), '--runner', '', '--harness-path', '']), 2)

    def test_run_checked_combines_all_codes_and_actual_runner_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / 'runner.py'
            harness = root / 'harness.py'
            report = root / 'report.json'
            policy = root / 'policy.json'
            harness.write_text('pass', encoding='utf-8')
            policy.write_text(json.dumps(self.policy), encoding='utf-8')
            for runner_code in (0, 1, 2, 3, 7):
                for kind, checker_code in [('valid', 0), ('attack', 1), ('error', 2), ('unclear', 3)]:
                    expected = 2 if runner_code not in (0, 1, 3) or checker_code == 2 else 1 if 1 in (runner_code, checker_code) else 3 if 3 in (runner_code, checker_code) else 0
                    with self.subTest(runner=runner_code, checker=checker_code):
                        if report.exists():
                            report.unlink()
                        runner.write_text("import argparse,sys\nfrom pathlib import Path\np=argparse.ArgumentParser()\np.add_argument('--harness-path',required=True)\np.add_argument('--report',required=True)\na=p.parse_args()\nassert a.harness_path == " + repr(str(harness)) + "\nassert a.report == " + repr(str(report)) + "\nPath(a.report).write_text(" + repr(json.dumps(canary_fixture(self.policy, kind))) + ",encoding='utf-8')" + f'\nsys.exit({runner_code})\n', encoding='utf-8')
                        self.assertEqual(self.checker.run_checked(runner, harness, report, policy), expected)
            report.unlink()
            runner.write_text('raise SystemExit(0)', encoding='utf-8')
            self.assertEqual(self.checker.run_checked(runner, harness, report, policy), 2)

    def test_launch_rejects_existing_report_without_running_or_overwriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / 'report.json'
            policy = root / 'policy.json'
            policy.write_text(json.dumps(self.policy), encoding='utf-8')
            original = json.dumps(self.report).encode('utf-8')
            report.write_bytes(original)
            with patch.object(self.checker.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as launch:
                self.assertEqual(self.checker.run_checked(root / 'runner.py', root / 'harness.py', report, policy), 2)
                launch.assert_not_called()
            self.assertEqual(report.read_bytes(), original)
            report.unlink()
            target = root / 'absent.json'
            report.symlink_to(target)
            with patch.object(self.checker.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as launch:
                self.assertEqual(self.checker.run_checked(root / 'runner.py', root / 'harness.py', report, policy), 2)
                launch.assert_not_called()
            self.assertTrue(report.is_symlink())
            self.assertEqual(report.readlink(), target)
            self.assertFalse(target.exists())

    def test_launch_fresh_report_omitted_by_successful_runner_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / 'runner.py'
            runner.write_text('raise SystemExit(0)', encoding='utf-8')
            policy = root / 'policy.json'
            policy.write_text(json.dumps(self.policy), encoding='utf-8')
            self.assertEqual(self.checker.run_checked(runner, root / 'harness.py', root / 'report.json', policy), 2)

    def test_launch_exception_still_checks_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root / 'policy.json'
            report = root / 'report.json'
            policy.write_text(json.dumps(self.policy), encoding='utf-8')
            with patch.object(self.checker.subprocess, 'run', side_effect=OSError('launch failed')), patch.object(self.checker, '_check_files', wraps=self.checker._check_files) as check_files:
                self.assertEqual(self.checker.run_checked(root / 'runner.py', root / 'harness.py', report, policy), 2)
                check_files.assert_called_once_with(report, policy)

    def test_launch_cli_uses_local_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'runner.py').write_text("import argparse\nfrom pathlib import Path\np=argparse.ArgumentParser()\np.add_argument('--harness-path',required=True)\np.add_argument('--report',required=True)\na=p.parse_args()\nPath(a.report).write_text(" + repr(json.dumps(self.report)) + ",encoding='utf-8')\nraise SystemExit(3)", encoding='utf-8')
            (root / 'harness.py').write_text('pass', encoding='utf-8')
            (root / 'policy.json').write_text(json.dumps(self.policy), encoding='utf-8')
            child = subprocess.run([sys.executable, '-I', str(CHECKER), '--runner', 'runner.py', '--harness-path', 'harness.py', '--report', 'report.json', '--policy', 'policy.json'], cwd=root, capture_output=True, check=False)
            self.assertEqual(child.returncode, 3, child.stderr)

    def test_vendored_hash_root_and_isolated_import(self):
        self.assertEqual(hashlib.sha256(HARNESS.read_bytes()).hexdigest(), CANONICAL_SHA256)
        self.assertEqual(HARNESS.resolve().parents[4], ROOT)
        child = subprocess.run([sys.executable, '-I', '-B', '-c', "import importlib.util; from pathlib import Path; p=Path(" + repr(str(HARNESS)) + "); s=importlib.util.spec_from_file_location('vendored',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert len(m.ADVERSARIAL_VECTORS)==14; assert m.VAULT_ROOT == p.parents[4]"], capture_output=True, check=False)
        self.assertEqual(child.returncode, 0, child.stderr)

    def test_vendored_mock_packaging_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            for flag, expected in [('--mock', 1), ('--mock-hardened', 0)]:
                output = Path(temporary) / flag.lstrip('-')
                child = subprocess.run([sys.executable, '-I', str(HARNESS), flag, '--quiet', '--out-dir', str(output)], capture_output=True, check=False)
                self.assertEqual(child.returncode, expected, child.stderr)
                self.assertEqual(len(list(output.glob('*.json'))), 1)
                self.assertEqual(len(list(output.glob('*.md'))), 1)


def main():
    if '--emit-canary' not in sys.argv:
        unittest.main()
        return 0
    parser = argparse.ArgumentParser(description='Emit synthetic checker canaries, never application resistance evidence.')
    parser.add_argument('--emit-canary', choices=['attack', 'error', 'unclear', 'abandon', 'missing', 'valid'], required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    policy = json.loads(Path(args.policy).read_text(encoding='utf-8'))
    Path(args.report).write_text(json.dumps(canary_fixture(policy, args.emit_canary), indent=2) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
