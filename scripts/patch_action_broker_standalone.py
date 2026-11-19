with open("action_broker.py", "rb") as f:
    content = f.read().decode("utf-8")

old_standalone = """        elif standalone_mode:
            # Explicit standalone in-process mode (zero test env flags)
            self.supervisor = helm_supervisor.PolicySupervisor()"""

new_standalone = """        elif standalone_mode:
            # Explicit standalone in-process mode (zero test env flags)
            self.supervisor = helm_supervisor.PolicySupervisor(enforce_dirty_check=False)"""

old_end_of_broker = """        except helm_supervisor.CompleteMediationBreachError as cme:
            self.supervisor._transition_to_locked(f"Complete mediation violation: {cme}")
            return False, f"Security Gate: {cme}", None
        except Exception as e:
            return False, f"Execution failed: {e}", None


_GLOBAL_BROKER: Optional[ActionBroker] = None"""

new_end_of_broker = """        except helm_supervisor.CompleteMediationBreachError as cme:
            self.supervisor._transition_to_locked(f"Complete mediation violation: {cme}")
            return False, f"Security Gate: {cme}", None
        except Exception as e:
            return False, f"Execution failed: {e}", None

    def close(self):
        \"\"\"Orderly shutdown of broker supervisor and client.\"\"\"
        if self.supervisor:
            try:
                self.supervisor.clean_shutdown()
            except Exception:
                pass
        if self.client and hasattr(self.client, "close"):
            try:
                self.client.close()
            except Exception:
                pass


_GLOBAL_BROKER: Optional[ActionBroker] = None"""

crlf = "\r\n" in content
content_norm = content.replace("\r\n", "\n")

assert old_standalone in content_norm, "old_standalone not found"
assert old_end_of_broker in content_norm, "old_end_of_broker not found"

content_norm = content_norm.replace(old_standalone, new_standalone, 1)
content_norm = content_norm.replace(old_end_of_broker, new_end_of_broker, 1)

if crlf:
    final_content = content_norm.replace("\n", "\r\n")
else:
    final_content = content_norm

with open("action_broker.py", "wb") as f:
    f.write(final_content.encode("utf-8"))

print("Successfully patched action_broker.py")
