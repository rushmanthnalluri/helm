with open("device_registry.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "return marker.read().strip() == \"1\"" in line:
        # line i is the return statement, line i+1 is except, line i+2 is return False
        lines.insert(i + 3, "        return False\n")
        break

with open("device_registry.py", "w", encoding="utf-8") as f:
    f.writelines(lines)

print("Updated device_registry.py line-by-line [OK]")
