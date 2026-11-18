with open("phone_approval_portal.py", "rb") as f:
    c = f.read().decode("utf-8")

old_sec1 = """    # 1. Authoritative DB single-use record check
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
    except Exception as e:
        logger.debug("DB token consumption check error: %s", e)"""

new_sec1 = """    # 1. Authoritative DB single-use record check
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

old_step1 = """    # 1. Try in-memory cache
    with _ENROLLMENT_LOCK:
        exp = _CONSOLE_RECOVERY_TOKENS.pop(tok, None)
        if exp and now <= exp:
            try:
                import db_utils
                with db_utils.get_db() as conn:
                    conn.execute("UPDATE console_recovery_tokens SET consumed = 1 WHERE token_hash = ?", (token_hash,))
                    conn.commit()
            except Exception:
                pass
            return True"""

new_step1 = """    # 1. Try in-memory cache
    with _ENROLLMENT_LOCK:
        exp = _CONSOLE_RECOVERY_TOKENS.pop(tok, None)
        if exp and now <= exp:
            try:
                import db_utils
                with db_utils.get_db() as conn:
                    conn.execute("UPDATE console_recovery_tokens SET consumed = 1 WHERE token_hash = ?", (token_hash,))
                    conn.commit()
            except Exception:
                pass
            if os.path.exists(ADMIN_RECOVERY_TOKEN_PATH):
                try:
                    os.remove(ADMIN_RECOVERY_TOKEN_PATH)
                except Exception:
                    pass
            return True"""

crlf = "\r\n" in c
cn = c.replace("\r\n", "\n")
assert old_sec1 in cn, "old_sec1 not found in phone_approval_portal.py"
assert old_step1 in cn, "old_step1 not found in phone_approval_portal.py"

cn = cn.replace(old_sec1, new_sec1, 1)
cn = cn.replace(old_step1, new_step1, 1)

if crlf:
    cn = cn.replace("\n", "\r\n")

with open("phone_approval_portal.py", "wb") as f:
    f.write(cn.encode("utf-8"))

print("Successfully patched phone_approval_portal.py for recovery token single-use")
