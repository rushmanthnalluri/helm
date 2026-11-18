import os

with open("tests/test_durable_memory.py", "r", encoding="utf-8") as f:
    c = f.read()

target_setup = """    def setUp(self):
        import taint_tracker
        taint_tracker.clear_all_taints()
        taint_tracker.set_standalone_mode(True)
        import action_broker
        action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))
        self.temp_dir = tempfile.TemporaryDirectory()
        self.facts_file = Path(self.temp_dir.name) / "facts.json"
        self.store = DurableMemoryStore(self.facts_file)
        durable_memory.set_default_memory_store(self.store)"""

replacement_setup = """    def setUp(self):
        import homie_supervisor
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        import kill_switch
        kill_switch._KILL_SWITCH_ACTIVE = False
        kill_switch._ENGAGED_REASON = ""
        import taint_tracker
        taint_tracker.clear_all_taints()
        taint_tracker.set_standalone_mode(True)
        import action_broker
        action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))
        self.temp_dir = tempfile.TemporaryDirectory()
        self.facts_file = Path(self.temp_dir.name) / "facts.json"
        self.store = DurableMemoryStore(self.facts_file)
        durable_memory.set_default_memory_store(self.store)"""

assert target_setup in c, "target_setup not found"
c = c.replace(target_setup, replacement_setup)

target_teardown = """    def tearDown(self):
        durable_memory.set_default_memory_store(None)"""

replacement_teardown = """    def tearDown(self):
        durable_memory.set_default_memory_store(None)
        import homie_supervisor
        for p in [homie_supervisor.DIRTY_FLAG_PATH, homie_supervisor.CRASH_HISTORY_PATH]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass"""

assert target_teardown in c, "target_teardown not found"
c = c.replace(target_teardown, replacement_teardown)

with open("tests/test_durable_memory.py", "w", encoding="utf-8") as f:
    f.write(c)
print("Updated tests/test_durable_memory.py isolation [OK]")
