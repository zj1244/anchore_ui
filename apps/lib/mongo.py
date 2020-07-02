# -*- coding: UTF-8 -*-
import pymongo


class MongoDB(object):
    def __init__(self, host='', port=27017, username='', password=''):
        self.host = host
        self.port = port
        self.conn=""
        self.username = username
        self.password = password
        if self.username and self.password:
            self.conn = pymongo.MongoClient('mongodb://%s:%s@%s:%s/' % (self.username,self.password,self.host,self.port),connect=False)


        else:

            self.conn = pymongo.MongoClient(host=self.host, port=self.port,connect=False)

