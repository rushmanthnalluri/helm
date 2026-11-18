with open("rails_confirmation.py", "rb") as f:
    c = f.read().decode("utf-8")

old = 'return False, "DENIED: No enrolled device. Physical presence challenge gesture required for confirmation.", None'
new = 'return False, "DENIED: No mobile device enrolled. Physical presence challenge gesture required for confirmation.", None'

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
assert old in cn, "old not found in rails_confirmation.py"
cn = cn.replace(old, new, 1)
if crlf:
    cn = cn.replace("\n", "\r\n")

with open("rails_confirmation.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Successfully updated rails_confirmation.py message")
