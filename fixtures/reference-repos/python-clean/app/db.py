"""Fixture 'sano' (Python) para PDGSEGSOFT-23 -- equivalentes seguros de los
patrones vulnerables que las reglas Python activas buscan. No debe disparar
ningún hallazgo."""


def find_order(cursor, user_id):
    cursor.execute("SELECT id, total, status FROM orders WHERE user_id = %s", (user_id,))
    return cursor.fetchall()
