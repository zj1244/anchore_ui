# !/usr/bin/env python
# -*- coding: utf-8 -*-
from config import *
from common import validate_is_dict
from apps import mongo
import datetime


class Dependency(object):

    def __init__(self):
        self.mongo_dep_result = mongo.conn[MONGO_DB_NAME][MONGO_DEP_COLL]

        self.resp_result = {
            "code": 200,
            "msg": "success"
        }

    def save(self, req_data):
        validate_is_dict( "req_data",req_data)
        try:
            inster_dict = {
                "docker_url": req_data.get("docker_url", ""),
                "result": req_data.get("dependency"),
                "publisher": req_data.get("publisher"),
                "add_time": datetime.datetime.now()
            }

            self.mongo_dep_result.update({"docker_url": req_data.get("docker_url", "")}, {"$set": inster_dict}, upsert=True)
        except Exception as e:
            self.resp_result["code"] = 500
            self.resp_result["msg"] = e
        return self.resp_result

    def get(self, docker_url=None):
        try:
            find_result = self.mongo_dep_result.find_one({"docker_url": docker_url})
            if find_result:
                self.resp_result["result"] = find_result.get("result", "")
                self.resp_result["docker_url"] = find_result.get("docker_url", "")
                self.resp_result["publisher"] = find_result.get("publisher", "")
            else:
                self.resp_result.update({
                    "result": "",
                    "docker_url": "",
                    "publisher": ""
                })
        except Exception as e:
            self.resp_result["code"] = 500
            self.resp_result["msg"] = e

        return self.resp_result
