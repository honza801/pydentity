# coding: utf-8

import sqlite3
import time
import logging
import os.path

class Database:
    
    dbfile = ''
    connector = None

    def __init__(self, CONF):
        logging.basicConfig(level=logging.DEBUG)
        self.dbfile = CONF['DATABASE_FILE']
        if not os.path.exists(self.dbfile):
            self.create_db()

    def get_connector(self):
        logging.debug('get connector')
        if not self.connector:
            self.connector = sqlite3.connect(self.dbfile)
        return self.connector
    
    def get_cursor(self):
        logging.debug('get cursor')
        return self.get_connector().cursor()

    def create_db(self):
        if not os.path.exists(self.dbfile):
            logging.debug('create sqlist database file')
            open(self.dbfile, 'a').close()
        cur = self.get_cursor()
        logging.debug('create table')
        cur.execute("CREATE TABLE IF NOT EXISTS last_change (username text, time integer)")
        
    def update_password_last_change(self, username):
        cur = self.get_cursor()
        cur.execute("SELECT * FROM last_change WHERE username=?", (username,))
        if cur.fetchone():
            logging.debug(f'update last_change user {username}')
            cur.execute("UPDATE last_change SET time=? WHERE username=?", (int(time.time()), username))
        else:
            logging.debug(f'insert user {username}')
            cur.execute("INSERT INTO last_change(username,time) VALUES (?,?)", (username, int(time.time())))

    def close(self):
        logging.debug('commit&close sqlite connection')
        self.get_connector().commit()
        self.get_connector().close()


