import os

BASE_DIR = r"D:\homie"

# 1. Update action_broker.py
with open(os.path.join(BASE_DIR, "action_broker.py"), "r", encoding="utf-8") as f:
    ab = f.read()

if "def set_action_broker(" not in ab:
    ab = ab.replace(
        "def get_action_broker() -> ActionBroker:",
        "def set_action_broker(broker: Optional[ActionBroker] = None):\n    global _GLOBAL_BROKER\n    _GLOBAL_BROKER = broker\n\ndef get_action_broker() -> ActionBroker:"
    )
    with open(os.path.join(BASE_DIR, "action_broker.py"), "w", encoding="utf-8") as f:
        f.write(ab)
    print("Added set_action_broker to action_broker.py [OK]")

# 2. Update tests/conftest.py
with open(os.path.join(BASE_DIR, "tests", "conftest.py"), "r", encoding="utf-8") as f:
    conf = f.read()

target_conf = "    taint_tracker.set_standalone_mode(True)"
replacement_conf = "    taint_tracker.set_standalone_mode(True)\n    action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))"

if replacement_conf not in conf and target_conf in conf:
    conf = conf.replace(target_conf, replacement_conf, 1)
    with open(os.path.join(BASE_DIR, "tests", "conftest.py"), "w", encoding="utf-8") as f:
        f.write(conf)
    print("Updated tests/conftest.py with standalone test double [OK]")

# 3. Update tests/test_durable_memory.py
with open(os.path.join(BASE_DIR, "tests", "test_durable_memory.py"), "r", encoding="utf-8") as f:
    tdm = f.read()

target_tdm = "        taint_tracker.set_standalone_mode(True)"
replacement_tdm = "        taint_tracker.set_standalone_mode(True)\n        import action_broker\n        action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))"

if replacement_tdm not in tdm and target_tdm in tdm:
    tdm = tdm.replace(target_tdm, replacement_tdm, 1)
    with open(os.path.join(BASE_DIR, "tests", "test_durable_memory.py"), "w", encoding="utf-8") as f:
        f.write(tdm)
    print("Updated tests/test_durable_memory.py with standalone test double [OK]")
