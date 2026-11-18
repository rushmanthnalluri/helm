# 1. Patch test_skill_compiler_and_recovery.py
with open("tests/test_skill_compiler_and_recovery.py", "rb") as f:
    c = f.read().decode("utf-8")

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
old = "        action_broker._GLOBAL_BROKER = None"
new = "        action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))"

cn = cn.replace(old, new)
if crlf:
    cn = cn.replace("\n", "\r\n")

with open("tests/test_skill_compiler_and_recovery.py", "wb") as f:
    f.write(cn.encode("utf-8"))

# 2. Patch test_unified_action_broker.py
with open("tests/test_unified_action_broker.py", "rb") as f:
    c2 = f.read().decode("utf-8")

crlf2 = "\r\n" in c2
cn2 = c2.replace("\r\n", "\n")
old2 = "        action_broker._GLOBAL_BROKER = None"
new2 = "        action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))"

# Replace in setUp
cn2 = cn2.replace("    def setUp(self):\n        os.environ[\"HOMIE_TEST_ENV\"] = \"1\"\n        os.environ[\"HOMIE_COMPLETE_MEDIATION\"] = \"1\"\n        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:\n            if os.path.exists(p):\n                try:\n                    os.remove(p)\n                except Exception:\n                    pass\n        kill_switch._KILL_SWITCH_ACTIVE = False\n        kill_switch._ENGAGED_REASON = \"\"\n        taint_tracker.clear_all_taints()\n        action_broker._GLOBAL_BROKER = None",
                  "    def setUp(self):\n        os.environ[\"HOMIE_TEST_ENV\"] = \"1\"\n        os.environ[\"HOMIE_COMPLETE_MEDIATION\"] = \"1\"\n        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:\n            if os.path.exists(p):\n                try:\n                    os.remove(p)\n                except Exception:\n                    pass\n        kill_switch._KILL_SWITCH_ACTIVE = False\n        kill_switch._ENGAGED_REASON = \"\"\n        taint_tracker.clear_all_taints()\n        action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))")

if crlf2:
    cn2 = cn2.replace("\n", "\r\n")

with open("tests/test_unified_action_broker.py", "wb") as f:
    f.write(cn2.encode("utf-8"))

print("Successfully patched test_skill_compiler_and_recovery and test_unified_action_broker")
