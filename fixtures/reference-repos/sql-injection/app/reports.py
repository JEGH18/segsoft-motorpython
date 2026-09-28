"""Fixture con SQL Injection real (Python) para PDGSEGSOFT-23."""


def unsafe_order_lookup(cursor, user_id):
    cursor.execute(f"SELECT * FROM orders WHERE user_id = {user_id}")
    return cursor.fetchall()


def safe_order_lookup(cursor, user_id):
    cursor.execute("SELECT id, total FROM orders WHERE user_id = %s", (user_id,))
    return cursor.fetchall()
