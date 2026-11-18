with open("tests/test_batch7.py", "rb") as f:
    c = f.read().decode("utf-8")

old = """        # Search on screen fast command
        handled3, msg3 = homie.try_fast_command("find on screen test_batch7.py")"""

new = """        # Search on screen fast command
        import semantic_screen_memory
        semantic_screen_memory.record_screen_event("code.exe", "test_batch7.py - homie", "def test_something(): pass")
        handled3, msg3 = homie.try_fast_command("find on screen test_batch7.py")"""

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
assert old in cn, "old not found in tests/test_batch7.py"
cn = cn.replace(old, new, 1)
if crlf:
    cn = cn.replace("\n", "\r\n")

with open("tests/test_batch7.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Successfully patched tests/test_batch7.py")
