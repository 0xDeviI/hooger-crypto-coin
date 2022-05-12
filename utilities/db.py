from textwrap import indent
from tinydb import TinyDB, Query
import os
import sys

class Database:
    dbName = None
    dbPath = None
    db = None
    def __init__(self, dbName, dbPath):
        self.dbName = dbName
        self.dbPath = dbPath if dbPath[-1] == '/' else dbPath + '/'
        self.initilize_db_path(self.dbPath)
        self.db = TinyDB(dbPath + dbName, indent=4, sort_keys=True, separators=(',', ':'))
        
    def initilize_db_path(self, path):
        if (os.path.exists(path) == False):
            os.makedirs(path)
        
    def query(self, table, query):
        table = self.db.table(table)
        return table.search(query)
        
    def insertOrUpdate(self, table, data):
        table = self.db.table(table)
        table.upsert(data, Query().id == data['id'])
        return True
        
    def insert(self, table, data):
        table = self.db.table(table)
        table.insert(data)
        return True
    
    def close_db(self):
        self.db.close()