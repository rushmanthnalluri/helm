with open("homie_supervisor.py", "rb") as f:
    c = f.read().decode("utf-8")

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")

old_def = """def verify_signed_approval_evidence(
    blob_raw: Any,
    caller_id: str,
    tool: str,
    args_hash: str,
    taint_epoch: int
) -> bool:"""

new_def = """def verify_signed_approval_evidence(
    blob_raw: Any,
    caller_id: str,
    tool: str,
    args_hash: str,
    taint_epoch: int,
    check_nonce: bool = True
) -> bool:"""

old_nonce_block = """        # Anti-replay: atomically check and record consumed nonce in supervisor/device_registry
        nonce = blob.get("nonce")
        expiry = int(float(blob.get("expiry", 0)))
        if not nonce or len(str(nonce)) < 8:
            logger.warning("Rejected approval evidence: invalid or missing nonce")
            return False

        if not device_registry.check_and_record_consumed_nonce(str(nonce), expiry):
            logger.warning("Rejected replayed approval evidence: nonce '%s' already consumed", nonce)
            return False"""

new_nonce_block = """        if check_nonce:
            # Anti-replay: atomically check and record consumed nonce in supervisor/device_registry
            nonce = blob.get("nonce")
            expiry = int(float(blob.get("expiry", 0)))
            if not nonce or len(str(nonce)) < 8:
                logger.warning("Rejected approval evidence: invalid or missing nonce")
                return False

            if not device_registry.check_and_record_consumed_nonce(str(nonce), expiry):
                logger.warning("Rejected replayed approval evidence: nonce '%s' already consumed", nonce)
                return False"""

old_sqlite_call = "if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):"
new_sqlite_call = "if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch, check_nonce=False):"

assert old_def in cn, "old_def not found"
assert old_nonce_block in cn, "old_nonce_block not found"
assert old_sqlite_call in cn, "old_sqlite_call not found"

cn = cn.replace(old_def, new_def, 1)
cn = cn.replace(old_nonce_block, new_nonce_block, 1)
cn = cn.replace(old_sqlite_call, new_sqlite_call, 1)

if crlf:
    cn = cn.replace("\n", "\r\n")

with open("homie_supervisor.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Successfully patched homie_supervisor.py for Mutation 69.")
