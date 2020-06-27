# !/usr/bin/env python
# -*- coding: utf-8 -*-
from common import sync_data
from app import apscheduler, log


class Scheduler(object):

    def __init__(self, scheduler_name="sync_anchore_data"):
        self.scheduler_name = scheduler_name
        self.final_result = {
            "status": "error",
            "content": "错误",
            "data": {}
        }

    def refresh(self):
        if sync_data():
            self.final_result["status"] = "success"
            self.final_result["content"] = "同步数据成功"

        else:
            self.final_result["status"] = "error"
            self.final_result["content"] = "同步数据失败"
        return self.final_result

    def add(self, job_time=None, job_unit=None):
        try:
            job_time = float(job_time)

            # job_unit = "hours" if job_unit == "hours" else "minutes"

            job = apscheduler.add_job(func="app.lib.common:sync_data", id=self.scheduler_name,
                                      trigger="interval",
                                      replace_existing=True, **{job_unit: job_time})
        except:
            log.exception("添加计划任务出错")
            self.final_result["status"] = "error"
            self.final_result["content"] = "添加计划任务出错"

        self.final_result["status"] = "success"
        self.final_result["content"] = "添加计划任务成功"
        self.final_result["redirect"] = "/images_sync"

        return self.final_result

    def remove(self):
        try:
            apscheduler.delete_job(id=self.scheduler_name)
            self.final_result["status"] = "success"
            self.final_result["content"] = "清空计划任务"
        except:
            log.exception("清空计划任务出错")
            self.final_result["status"] = "error"
            self.final_result["content"] = "清空计划任务出错"
        return self.final_result
    def get(self):
        aps = apscheduler.get_job(id=self.scheduler_name)
        if aps:
            if aps.next_run_time:
                next_run_time = aps.next_run_time.strftime(
                    "%Y-%m-%d %H:%M:%S")
                self.final_result = {
                    "status": "success",
                    "content": "获取计划任务成功",
                    "data": {
                        "id": self.scheduler_name,
                        "next_run_time": next_run_time
                    }
                }
        else:
            self.final_result = {
                "status": "success",
                "content": "获取计划任务成功",
                "data": {"id": self.scheduler_name, "next_run_time": ""}
            }
        return self.final_result
