"""A small, deliberately clean program used to demonstrate a passing scan."""

import sqlite3


def find_user(conn: sqlite3.Connection, username: str):
    return conn.execute("SELECT id, name FROM users WHERE name = ?", (username,)).fetchall()


if __name__ == "__main__":
    print("hello")
