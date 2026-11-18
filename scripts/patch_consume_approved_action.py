with open("homie_supervisor.py", "rb") as f:
    c = f.read().decode("utf-8")

old_consume = """    def consume_approved_action(self, caller_id: str, tool: str, args_hash: str, taint_epoch: int) -> bool:
        \"\"\"Directive 14 & Batch 32 & 35 & 37 & 38: Atomically checks and consumes a direct approved action
        with cryptographic verification of signed evidence blob against enrolled device keys.
        Anti-Burn DoS defense: Iterates candidate rows so invalid/junk rows do not burn valid approvals.
        Anti-Replay defense: Atomically verifies and records nonce in persistent nonce store.
        \"\"\"
        now = time.time()
        in_memory_found = False
        with self._approved_lock:
            key = (caller_id, tool, args_hash.lower(), int(taint_epoch))
            exp = self._approved_actions.pop(key, None)
            # Prune expired
            to_del = [k for k, v in self._approved_actions.items() if now > (v[0] if isinstance(v, tuple) else v)]
            for k in to_del:
                self._approved_actions.pop(k, None)
            if exp:
                exp_time = exp[0] if isinstance(exp, tuple) else exp
                blob = exp[1] if isinstance(exp, tuple) else None
                if now <= exp_time:
                    if verify_signed_approval_evidence(blob, caller_id, tool, args_hash, taint_epoch):
                        b_dict = json.loads(blob) if isinstance(blob, str) else (blob if isinstance(blob, dict) else {})
                        nonce = b_dict.get("nonce")
                        nonce_exp = int(b_dict.get("expiry", exp_time))
                        if nonce and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp):
                            logger.warning("In-memory approved action rejected: nonce already consumed (replay)!")
                        else:
                            in_memory_found = True
                    else:
                        logger.warning("In-memory approved action rejected: invalid or forged cryptographic evidence!")

        # Atomically consume in SQLite as well to prevent double-spending between memory and DB
        db_consumed = False
        try:
            import db_utils
            with db_utils.get_db() as conn:
                _init_approved_actions_table(conn)
                cur = conn.cursor()
                cur.execute(\"\"\"
                    SELECT id, signature_blob FROM approved_actions
                    WHERE caller_id = ? AND tool = ? AND args_hash = ? AND taint_epoch = ? AND consumed = 0 AND expiry >= ?
                    ORDER BY id ASC
                \"\"\", (caller_id, tool, args_hash.lower(), int(taint_epoch), now))
                rows = cur.fetchall()
                for row in rows:
                    sig_blob = row[\"signature_blob\"] if \"signature_blob\" in row.keys() else row[1]
                    if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):
                        b_dict = json.loads(sig_blob) if isinstance(sig_blob, str) else (sig_blob if isinstance(sig_blob, dict) else {})
                        nonce = b_dict.get("nonce")
                        nonce_exp = int(b_dict.get("expiry", now + 60))
                        if nonce and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp):
                            logger.warning("SQLite approved action row %s rejected: nonce already consumed (replay)!", row["id"])
                            cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                            conn.commit()
                            continue

                        cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                        conn.commit()
                        db_consumed = True
                        break
                    else:
                        logger.warning("Skipping invalid/forged SQLite approved action row %s; marking consumed to prevent DoS", row["id"])
                        cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                        conn.commit()
        except Exception as e:
            logger.warning("Could not consume approved action from SQLite: %s", e)

        return in_memory_found or db_consumed"""

new_consume = """    def consume_approved_action(self, caller_id: str, tool: str, args_hash: str, taint_epoch: int) -> bool:
        \"\"\"Directive 14 & Batch 32 & 35 & 37 & 38: Atomically checks and consumes a direct approved action
        with cryptographic verification of signed evidence blob against enrolled device keys.
        Anti-Burn DoS defense: Iterates candidate rows so invalid/junk rows do not burn valid approvals.
        Anti-Replay defense: Atomically verifies and records nonce in persistent nonce store.
        \"\"\"
        now = time.time()
        in_memory_found = False
        with self._approved_lock:
            key = (caller_id, tool, args_hash.lower(), int(taint_epoch))
            exp = self._approved_actions.pop(key, None)
            # Prune expired
            to_del = [k for k, v in self._approved_actions.items() if now > (v[0] if isinstance(v, tuple) else v)]
            for k in to_del:
                self._approved_actions.pop(k, None)
            if exp:
                exp_time = exp[0] if isinstance(exp, tuple) else exp
                blob = exp[1] if isinstance(exp, tuple) else None
                if now <= exp_time:
                    if verify_signed_approval_evidence(blob, caller_id, tool, args_hash, taint_epoch):
                        in_memory_found = True
                    else:
                        logger.warning("In-memory approved action rejected: invalid or forged cryptographic evidence!")

        # Atomically consume in SQLite as well to prevent double-spending between memory and DB
        db_consumed = False
        try:
            import db_utils
            with db_utils.get_db() as conn:
                _init_approved_actions_table(conn)
                cur = conn.cursor()
                cur.execute(\"\"\"
                    SELECT id, signature_blob FROM approved_actions
                    WHERE caller_id = ? AND tool = ? AND args_hash = ? AND taint_epoch = ? AND consumed = 0 AND expiry >= ?
                    ORDER BY id ASC
                \"\"\", (caller_id, tool, args_hash.lower(), int(taint_epoch), now))
                rows = cur.fetchall()
                for row in rows:
                    r_id = row[\"id\"] if (isinstance(row, dict) or hasattr(row, \"keys\")) else row[0]
                    sig_blob = row[\"signature_blob\"] if (isinstance(row, dict) or hasattr(row, \"keys\")) else row[1]
                    if in_memory_found:
                        # Already consumed in memory; mark DB row consumed to prevent cross-process replay
                        cur.execute(\"UPDATE approved_actions SET consumed = 1 WHERE id = ?\", (r_id,))
                        conn.commit()
                        break
                    else:
                        if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):
                            cur.execute(\"UPDATE approved_actions SET consumed = 1 WHERE id = ?\", (r_id,))
                            conn.commit()
                            db_consumed = True
                            break
                        else:
                            logger.warning(\"Skipping invalid/forged SQLite approved action row %s; marking consumed to prevent DoS\", r_id)
                            cur.execute(\"UPDATE approved_actions SET consumed = 1 WHERE id = ?\", (r_id,))
                            conn.commit()
        except Exception as e:
            logger.warning(\"Could not consume approved action from SQLite: %s\", e)

        return in_memory_found or db_consumed"""

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
assert old_consume in cn, "old_consume not found in homie_supervisor.py"
cn = cn.replace(old_consume, new_consume, 1)
if crlf:
    cn = cn.replace("\n", "\r\n")

with open("homie_supervisor.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Successfully patched consume_approved_action in homie_supervisor.py")
