with open("rails_confirmation.py", "rb") as f:
    c = f.read().decode("utf-8")

old = """            else:
                # No enrolled mobile device: strictly deny consequential actions under zero-trust doctrine
                return False, "DENIED: No mobile device enrolled. All consequential tools strictly require approval from an enrolled phone.", None"""

new = """            else:
                # No enrolled mobile device: requires physical presence gesture matching ephemeral challenge
                if not presence_gesture:
                    return False, "DENIED: No enrolled device. Physical presence challenge gesture required for confirmation.", None
                if not req.presence_challenge or not hmac.compare_digest(str(presence_gesture).strip(), str(req.presence_challenge).strip()):
                    return False, "DENIED: Invalid physical presence challenge gesture.", None"""

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
assert old in cn, "old text not found in rails_confirmation.py"
cn = cn.replace(old, new, 1)
if crlf:
    cn = cn.replace("\n", "\r\n")

with open("rails_confirmation.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Patched rails_confirmation.py successfully")
