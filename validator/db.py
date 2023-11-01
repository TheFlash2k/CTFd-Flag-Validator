import sqlite3

class Database:

    def __init__(self, db_name : str = "flags.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS flags (id INTEGER PRIMARY KEY, flag TEXT, team_id TEXT, chal_id TEXT)")
        self.conn.commit()

    def __del__(self):
        self.conn.close()

    def insert(self, flag: str, team_id: str, chal_id: str):
        self.cursor.execute("INSERT INTO flags (flag, team_id, chal_id) VALUES (?, ?, ?)", (flag, team_id, chal_id))
        self.conn.commit()

    def get(self, flag: str):
        self.cursor.execute("SELECT * FROM flags WHERE flag=?", (flag,))
        return self.cursor.fetchall()
    
    def get_specific(self, chal_id: str, team_id: str):
        self.cursor.execute("SELECT * FROM flags WHERE chal_id=? AND team_id=?", (chal_id, team_id))
        return self.cursor.fetchall()

    def get_all(self):
        self.cursor.execute("SELECT * FROM flags")
        return self.cursor.fetchall()
    
    def delete(self, flag: str):
        self.cursor.execute("DELETE FROM flags WHERE flag=?", (flag,))
        self.conn.commit()

    def delete_all(self):
        self.cursor.execute("DELETE FROM flags")
        self.conn.commit()