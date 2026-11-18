import os
import sys
import unittest
import traceback
import io

def run_diagnostics():
    test_dir = os.path.join(os.path.dirname(__file__), "..", "tests")
    test_dir = os.path.abspath(test_dir)
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=test_dir, pattern="test_*.py")

    print(f"Discovered {suite.countTestCases()} test cases.")

    test_files = [f for f in os.listdir(test_dir) if f.startswith("test_") and f.endswith(".py")]
    test_files.sort()

    results_by_file = {}
    total_passed = 0
    total_failed = 0
    total_errors = 0
    total_skipped = 0

    for tf in test_files:
        module_name = f"tests.{tf[:-3]}"
        try:
            mod_suite = loader.loadTestsFromName(module_name)
        except Exception as e:
            results_by_file[tf] = {
                "load_error": str(e),
                "traceback": traceback.format_exc(),
                "tests": 0, "passed": 0, "failed": 0, "errors": 1, "skipped": 0, "failures_detail": []
            }
            total_errors += 1
            continue

        runner_stream = io.StringIO()
        runner = unittest.TextTestRunner(stream=runner_stream, verbosity=0)
        res = runner.run(mod_suite)

        passed = res.testsRun - len(res.failures) - len(res.errors) - len(res.skipped)
        failures_detail = []
        for test, err in res.failures:
            failures_detail.append({"test": str(test), "type": "FAILURE", "err": err})
        for test, err in res.errors:
            failures_detail.append({"test": str(test), "type": "ERROR", "err": err})

        results_by_file[tf] = {
            "tests": res.testsRun,
            "passed": passed,
            "failed": len(res.failures),
            "errors": len(res.errors),
            "skipped": len(res.skipped),
            "failures_detail": failures_detail
        }
        total_passed += passed
        total_failed += len(res.failures)
        total_errors += len(res.errors)
        total_skipped += len(res.skipped)

    print("\n" + "="*80)
    print(f"TEST SUMMARY: Total: {total_passed + total_failed + total_errors + total_skipped} | Passed: {total_passed} | Failed: {total_failed} | Errors: {total_errors} | Skipped: {total_skipped}")
    print("="*80)

    problem_files = [tf for tf, d in results_by_file.items() if d.get("failed", 0) > 0 or d.get("errors", 0) > 0 or "load_error" in d]
    print(f"\nFiles with Failures/Errors ({len(problem_files)} files):")
    for tf in problem_files:
        d = results_by_file[tf]
        print(f"  - {tf}: {d.get('passed', 0)} passed, {d.get('failed', 0)} failed, {d.get('errors', 0)} errors")

    print("\n" + "="*80)
    print("DETAILED FAILURES & ERRORS:")
    print("="*80)
    for tf in problem_files:
        d = results_by_file[tf]
        print(f"\n>>> FILE: {tf}")
        if "load_error" in d:
            print(f"LOAD ERROR: {d['load_error']}\n{d['traceback']}")
        for f in d.get("failures_detail", []):
            print(f"[{f['type']}] {f['test']}")
            print("-" * 40)
            print(f['err'])
            print("-" * 40)

if __name__ == "__main__":
    run_diagnostics()
