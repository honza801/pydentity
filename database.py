# coding: utf-8

import sqlite3
import time

class Database:
    
    dbfile = ''
    connector = None

    def __init__(self, CONF):
        self.dbfile = CONF['DATABASE_FILE']

    def get_connector(self):
        if not self.connector:
            self.connector = sqlite3.connect(self.dbfile)
        return self.connector
    
    def get_cursor(self):
        return self.get_connector().cursor()

    def create_db(self):
        if not os.path.exists(self.dbfile):
            open(self.dbfile, 'a').close()
        cur = self.get_cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS last_change (username text, time integer)")
        
    def update_password_last_change(self, username):
        cur = self.get_cursor()
        cur.execute("SELECT * FROM last_change WHERE username=?", (username,))
        if cur.fetchone():
            cur.execute("UPDATE last_change SET time=? WHERE username=?", (int(time.time()), username))
        else:
            cur.execute("INSERT INTO last_change(username,time) VALUES (?,?)", (username, int(time.time())))

    def close(self):
        self.get_connector().commit()
        self.get_connector().close()


