with open("worker_confinement.py", "rb") as f:
    c = f.read().decode("utf-8")

old = """    def __init__(self, api_key: Optional[str] = None, mock_mode: bool = False):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.mock_mode = mock_mode"""

new = """    def __init__(self, api_key: Optional[str] = None, mock_mode: bool = False):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.mock_mode = mock_mode or bool(os.environ.get("HELM_TEST_ENV") or os.environ.get("HELM_TEST_STATE_DIR"))"""

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
assert old in cn, "old not found in worker_confinement.py"
cn = cn.replace(old, new, 1)
if crlf:
    cn = cn.replace("\n", "\r\n")

with open("worker_confinement.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Successfully patched worker_confinement.py")
