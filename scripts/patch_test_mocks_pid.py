# 1. Patch test_batch37_security_hardening.py
with open("tests/test_batch37_security_hardening.py", "rb") as f:
    c37 = f.read().decode("utf-8")
old37 = 'return_value={"proc_name": "powershell.exe", "hwnd": 555}'
new37 = 'return_value={"proc_name": "powershell.exe", "hwnd": 555, "pid": 555}'
assert old37 in c37
c37 = c37.replace(old37, new37)
with open("tests/test_batch37_security_hardening.py", "wb") as f:
    f.write(c37.encode("utf-8"))

# 2. Patch test_batch38_security_hardening.py
with open("tests/test_batch38_security_hardening.py", "rb") as f:
    c38 = f.read().decode("utf-8")
old38 = 'return_value={"proc_name": "calc.exe", "hwnd": 12345}'
new38 = 'return_value={"proc_name": "calc.exe", "hwnd": 12345, "pid": 12345}'
assert old38 in c38
c38 = c38.replace(old38, new38)
with open("tests/test_batch38_security_hardening.py", "wb") as f:
    f.write(c38.encode("utf-8"))

# 3. Patch test_batch39_security_hardening.py
with open("tests/test_batch39_security_hardening.py", "rb") as f:
    c39 = f.read().decode("utf-8")
old39 = '        with patch.object(windows_tools, "get_window_under_point", return_value=(12345, mock_info)):'
new39 = '''        with patch.object(windows_tools, "get_foreground_window", return_value={"pid": 11111, "proc_name": "notepad.exe", "hwnd": 22222}), \\
             patch.object(windows_tools, "get_window_under_point", return_value=(12345, mock_info)):'''
assert old39 in c39.replace("\r\n", "\n")
c39_norm = c39.replace("\r\n", "\n").replace(old39, new39)
if "\r\n" in c39:
    c39_norm = c39_norm.replace("\n", "\r\n")
with open("tests/test_batch39_security_hardening.py", "wb") as f:
    f.write(c39_norm.encode("utf-8"))

# 4. Patch test_batch41_security_hardening.py
with open("tests/test_batch41_security_hardening.py", "rb") as f:
    c41 = f.read().decode("utf-8")
old41 = '        with patch.object(windows_tools, "get_window_under_point", return_value=(12345, spoofed_window_info)):'
new41 = '''        with patch.object(windows_tools, "get_foreground_window", return_value={"pid": 11111, "proc_name": "notepad.exe", "hwnd": 22222}), \\
             patch.object(windows_tools, "get_window_under_point", return_value=(12345, spoofed_window_info)):'''
assert old41 in c41.replace("\r\n", "\n")
c41_norm = c41.replace("\r\n", "\n").replace(old41, new41)
if "\r\n" in c41:
    c41_norm = c41_norm.replace("\n", "\r\n")
with open("tests/test_batch41_security_hardening.py", "wb") as f:
    f.write(c41_norm.encode("utf-8"))

print("Successfully patched test mocks with pid")
