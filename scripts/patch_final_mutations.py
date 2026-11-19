import os

# 1. Update phone_approval_portal.py
with open("phone_approval_portal.py", "rb") as f:
    c = f.read().decode("utf-8")

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")

old_db = """    # 1. Authoritative DB single-use record check
    db_checked = False
    try:
        import db_utils
        _init_recovery_tokens_table()
        with db_utils.get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT consumed, expires_at FROM console_recovery_tokens WHERE token_hash = ?", (tok_hash,))
            row = cur.fetchone()
            if row:
                db_checked = True
                if row[0] == 0 and now <= row[1]:
                    conn.execute("UPDATE console_recovery_tokens SET consumed = 1 WHERE token_hash = ?", (tok_hash,))
                    conn.commit()
                    logger.info("Admin recovery token consumed via authoritative DB record")
                    if os.path.exists(ADMIN_RECOVERY_TOKEN_PATH):
                        try:
                            os.remove(ADMIN_RECOVERY_TOKEN_PATH)
                        except Exception:
                            pass
                    return True
                else:
                    if os.path.exists(ADMIN_RECOVERY_TOKEN_PATH):
                        try:
                            os.remove(ADMIN_RECOVERY_TOKEN_PATH)
                        except Exception:
                            pass
                    return False
    except Exception as e:
        logger.debug("DB token consumption check error: %s", e)

    if db_checked:
        return False"""

new_db = """    # 1. Authoritative DB single-use record check
    try:
        import db_utils
        _init_recovery_tokens_table()
        with db_utils.get_db() as conn:
            cursor = conn.execute(
                "UPDATE console_recovery_tokens SET consumed = 1 WHERE token_hash = ? AND consumed = 0 AND expires_at > ?",
                (tok_hash, now)
            )
            conn.commit()
            if cursor.rowcount > 0:
                logger.info("Admin recovery token consumed via authoritative DB record")
                if os.path.exists(ADMIN_RECOVERY_TOKEN_PATH):
                    try:
                        os.remove(ADMIN_RECOVERY_TOKEN_PATH)
                    except Exception:
                        pass
                return True
            else:
                cur = conn.cursor()
                cur.execute("SELECT rowid FROM console_recovery_tokens WHERE token_hash = ?", (tok_hash,))
                if cur.fetchone():
                    if os.path.exists(ADMIN_RECOVERY_TOKEN_PATH):
                        try:
                            os.remove(ADMIN_RECOVERY_TOKEN_PATH)
                        except Exception:
                            pass
                    return False
    except Exception as e:
        logger.debug("DB token consumption check error: %s", e)"""

assert old_db in cn, "old_db not found"
cn = cn.replace(old_db, new_db, 1)

if crlf:
    cn = cn.replace("\n", "\r\n")

with open("phone_approval_portal.py", "wb") as f:
    f.write(cn.encode("utf-8"))

# 2. Update helm_supervisor.py
with open("helm_supervisor.py", "rb") as f:
    cs = f.read().decode("utf-8")

crlf_s = "\r\n" in cs
cns = cs.replace("\r\n", "\n")

old_sup_loop = """                for row in rows:
                    r_id = row["id"] if (isinstance(row, dict) or hasattr(row, "keys")) else row[0]
                    sig_blob = row["signature_blob"] if (isinstance(row, dict) or hasattr(row, "keys")) else row[1]
                    if in_memory_found:
                        # Already consumed in memory; mark DB row consumed to prevent cross-process replay
                        cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (r_id,))
                        conn.commit()
                        break
                    else:
                        if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):
                            cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (r_id,))
                            conn.commit()
                            db_consumed = True
                            break
                        else:
                            logger.warning("Skipping invalid/forged SQLite approved action row %s; marking consumed to prevent DoS", r_id)
                            cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (r_id,))
                            conn.commit()"""

new_sup_loop = """                for row in rows:
                    sig_blob = row["signature_blob"] if "signature_blob" in row.keys() else row[1]
                    if in_memory_found:
                        # Already consumed in memory; mark DB row consumed to prevent cross-process replay
                        cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                        conn.commit()
                        break
                    else:
                        b_dict = json.loads(sig_blob) if isinstance(sig_blob, str) else (sig_blob if isinstance(sig_blob, dict) else {})
                        nonce = b_dict.get("nonce")
                        nonce_exp = int(b_dict.get("expiry", now + 60))
                        if nonce and not device_registry.check_and_record_consumed_nonce(nonce, nonce_exp):
                            logger.warning("SQLite approved action row %s rejected: nonce already consumed (replay)!", row["id"])
                            cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                            conn.commit()
                            continue

                        if verify_signed_approval_evidence(sig_blob, caller_id, tool, args_hash, taint_epoch):
                            cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                            conn.commit()
                            db_consumed = True
                            break
                        else:
                            logger.warning("Skipping invalid/forged SQLite approved action row %s; marking consumed to prevent DoS", row["id"])
                            cur.execute("UPDATE approved_actions SET consumed = 1 WHERE id = ?", (row["id"],))
                            conn.commit()"""

assert old_sup_loop in cns, "old_sup_loop not found"
cns = cns.replace(old_sup_loop, new_sup_loop, 1)

if crlf_s:
    cns = cns.replace("\n", "\r\n")

with open("helm_supervisor.py", "wb") as f:
    f.write(cns.encode("utf-8"))

# 3. Update rails_confirmation.py and scripts/run_mutation_tests.py for Mutation 77
with open("rails_confirmation.py", "rb") as f:
    cr = f.read().decode("utf-8")

crlf_r = "\r\n" in cr
cnr = cr.replace("\r\n", "\n")

old_rails = 'return False, "DENIED: No mobile device enrolled. Physical presence challenge gesture required for confirmation.", None'
new_rails = 'return False, "DENIED: No mobile device enrolled. Physical presence challenge gesture required for confirmation. All consequential tools strictly require approval from an enrolled phone.", None'

assert old_rails in cnr, "old_rails not found"
cnr = cnr.replace(old_rails, new_rails, 1)

if crlf_r:
    cnr = cnr.replace("\n", "\r\n")

with open("rails_confirmation.py", "wb") as f:
    f.write(cnr.encode("utf-8"))

# 4. Update run_mutation_tests.py Mutation 77 target
with open("scripts/run_mutation_tests.py", "rb") as f:
    cm = f.read().decode("utf-8")

crlf_m = "\r\n" in cm
cnm = cm.replace("\r\n", "\n")

old_m77 = '"target": \'                return False, "DENIED: No mobile device enrolled. All consequential tools strictly require approval from an enrolled phone.", None\','
new_m77 = '"target": \'                return False, "DENIED: No mobile device enrolled. Physical presence challenge gesture required for confirmation. All consequential tools strictly require approval from an enrolled phone.", None\','

assert old_m77 in cnm, "old_m77 not found"
cnm = cnm.replace(old_m77, new_m77, 1)

if crlf_m:
    cnm = cnm.replace("\n", "\r\n")

with open("scripts/run_mutation_tests.py", "wb") as f:
    f.write(cnm.encode("utf-8"))

print("Successfully applied final mutation target patches.")
