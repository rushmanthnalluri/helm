with open("tests/test_hardened_phone_gateway.py", "rb") as f:
    c = f.read().decode("utf-8")

old = "        action_broker._GLOBAL_BROKER = None"
new = "        action_broker.set_action_broker(action_broker.ActionBroker(standalone_mode=True))"

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
assert old in cn, "old not found in tests/test_hardened_phone_gateway.py"
cn = cn.replace(old, new, 1)
if crlf:
    cn = cn.replace("\n", "\r\n")

with open("tests/test_hardened_phone_gateway.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Successfully patched tests/test_hardened_phone_gateway.py")
