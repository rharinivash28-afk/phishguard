"""Run every backend test module. No pytest required.

    python run_tests.py
"""
import runpy
import sys

MODULES = ["test_analyzer", "test_sessions", "test_security", "test_detection"]

failed = []
for mod in MODULES:
    print(f"\n=== {mod} ===")
    try:
        runpy.run_module(mod, run_name="__main__")
    except SystemExit as e:
        if e.code:
            failed.append(mod)

print("\n" + ("=" * 40))
if failed:
    print(f"FAILED: {', '.join(failed)}")
    sys.exit(1)
print("all test modules passed")
