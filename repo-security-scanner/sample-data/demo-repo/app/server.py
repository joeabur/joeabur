"""Intentionally vulnerable demo code. NOT for production use.

Every weakness below is deliberate so that the scanners have something to find.
"""
import hashlib
import sqlite3
import subprocess


def find_user(conn: sqlite3.Connection, username: str):
    # SQL injection: user input concatenated into the query (CWE-89).
    query = "SELECT id, name FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()


def ping(host: str) -> int:
    # Command injection: shell=True with user-controlled input (CWE-78).
    return subprocess.call("ping -c 1 " + host, shell=True)


def fingerprint(data: bytes) -> str:
    # Weak hash algorithm (CWE-327).
    return hashlib.md5(data).hexdigest()


def calculate(expression: str):
    # Code injection via eval (CWE-95).
    return eval(expression)
