# !/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import base64
import time
import re
import sys
import random
import requests
import collections
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tenacity import retry, wait_fixed, stop_after_attempt, before_log
from config import *
from apps import mongo, log

reload(sys)
sys.setdefaultencoding('utf8')
executor = ThreadPoolExecutor(10)
fix_version = {

}

poc = {

}


def timestamp2str(date):
    if date:

        return datetime.fromtimestamp(date).strftime("%Y-%m-%d %H:%M:%S")
    else:
        return ""


def get_header():
    header = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate'
    }
    return header


@retry(wait=wait_fixed(7), stop=stop_after_attempt(5))
def retry_get(url, **kwargs):
    log.debug(url)
    return requests.get(url=url, headers=get_header(), **kwargs)


def req(url, user="", pwd=""):
    resp_json = {}
    try:
        if user and pwd:
            session = requests.session()
            session.auth = (user, pwd)

            resp = session.get(url=url, headers=get_header())
        else:
            resp = requests.get(url=url, headers=get_header())

        if resp.status_code == 200:
            resp_json = resp.json()
    except:
        log.exception("req_url:%s" % url)

    return resp_json


def get_vuln_trend(project_name="", n=5):
    final_result = {
        "created_at": [],
        "critical": [],
        "high": [],
        "low": [],
        "medium": []

    }
    try:
        images = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL].find({"project_name": project_name}).sort(
            "created_at", -1).limit(n)

        if images.count():
            for i in images:
                final_result["created_at"].insert(0, timestamp2str(i["created_at"]))
                final_result["critical"].insert(0, i["risk"]["critical"])
                final_result["high"].insert(0, i["risk"]["high"])
                final_result["low"].insert(0, i["risk"]["low"])
                final_result["medium"].insert(0, i["risk"]["medium"])

    except:
        log.exception("error")

    return final_result


def validate_is_dict(option, value):
    if not isinstance(value, dict):
        raise TypeError("%s must be an instance of dict" % (option,))


def get_images_details(image_id=""):
    images_details = {}

    mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
    images = mongo_anchore_result.find_one({"imageId": image_id})
    if images:
        images_details["fulltag"] = images["fulltag"]
        images_details["project_name"] = images["project_name"]
        images_details["total_package"] = {}
        images_details["vulnerabilities"] = images["vulnerabilities"]
        images_details["publisher"] = images["publisher"]
        total_package_sum = mongo_anchore_result.aggregate([
            {'$match': {'imageId': image_id}},
            {"$unwind": "$vulnerabilities"},
            {"$group": {"_id": "$vulnerabilities.package_name", "sum": {"$sum": 1}}},
            {"$sort": {"sum": -1}},
            {"$limit": 10}
        ])
        for i in total_package_sum:
            images_details["total_package"][i["_id"]] = i["sum"]

        images_details["total_risk"] = images["risk"]
    return images_details


def get_pom_file(docker_url=""):
    result = ""
    if docker_url:
        find_result = mongo.conn[MONGO_DB_NAME][MONGO_DEP_COLL].find_one({"docker_url": docker_url})
        if find_result:
            result = base64.b64decode(find_result.get("result", ""))

    return result


def get_project():
    final_result = []
    mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
    images = mongo_anchore_result.find()
    if images.count():

        images_analysis = mongo_anchore_result.aggregate(
            [{"$group": {
                "_id": "$project_name",
                "last_time": {"$max": "$created_at"},
                "risk": {"$last": "$risk"},
                "created_at": {"$last": "$created_at"},
                "affected_package_count": {"$last": "$affected_package_count"},
                "imageId": {"$last": "$imageId"},
                "analysis_status": {"$last": "$analysis_status"},
                "publisher": {"$last": "$publisher"}
            }
            }, {"$sort": {"created_at": -1}}])
        for i in images_analysis:
            project_result = {}
            try:

                project_result["affected_package_count"] = i.get("affected_package_count", "")
                project_result["project_name"] = i["_id"]
                project_result["analyzed_at"] = timestamp2str(i["created_at"])
                project_result["imageId"] = i["imageId"]

                project_result["critical"] = i["risk"]["critical"]
                project_result["high"] = i["risk"]["high"]
                project_result["medium"] = i["risk"]["medium"]
                project_result["low"] = i["risk"]["low"]
                project_result["analysis_status"] = i["analysis_status"]
                project_result["publisher"] = i["publisher"]
                final_result.append(project_result)

            except:
                executor.submit(sync_data, imageId=i["imageId"], force=True)
                # sync_data(imageId=i["imageId"], force=True)
                log.exception(i)
    return final_result


def save_dependency():
    pass


def get_parents(input_dependency):
    dependency_list = []
    ouput = []
    while True:
        start = input_dependency.find("[INFO] +-")
        if start == -1:
            break
        end = input_dependency.find("[INFO] +-", start + 10)
        dependency_list.append(input_dependency[start:end])
        input_dependency = input_dependency[end:]

    for dependency in dependency_list:

        child_jar = []
        parents_and_version = ""
        parents_jar_name = ""
        group_id = ""
        match_obj = re.findall(r"- (.+):(.+):(.+):(.+):(.+)", dependency)
        if match_obj:
            parents_and_version = ":".join([match_obj[0][1], match_obj[0][3]])
            group_id = match_obj[0][0]
            parents_jar_name = match_obj[0][1]

            child_jar = [x[1] for x in match_obj[1:]]

        if len(child_jar) == 0:
            child_jar = [parents_jar_name]
        else:
            child_jar.append(match_obj[0][1])

        ouput.append({"group_id": group_id, "parents": parents_and_version, "child": child_jar})
    return ouput


def format_version(version, point):
    version_list = version.split(".")
    return ".".join(version_list[:point]) + "."


def get_version(group_id, package, image_id):
    package_version = {
        "last_version": "",
        "same_version": ""
    }
    package_name, current_package_version = package.split(":")
    if current_package_version.count(".") in [2, 3]:  # 8.0.28 or 2.2.2.RELEASE

        current_package_version = format_version(current_package_version, 2)

    elif current_package_version.count("-") == 1:
        current_package_version = current_package_version[:current_package_version.find("-")]
    else:
        log.info("未处理的版本号:%s image_id=%s" % (package, image_id))

    if fix_version.has_key(package_name):
        log.debug("找到%s的版本是%s" % (package_name, fix_version[package_name]))
        package_version = fix_version[package_name]
    else:
        while True:

            url = "https://mvnrepository.com/artifact/%s/%s" % (group_id, package_name)
            log.debug(url)

            resp = retry_get(url=url, verify=False)
            if resp.status_code == 403:
                log.info("查找包异常，status=%s" % resp.status_code)
                time.sleep(5)
            elif resp.status_code == 404:
                fix_version[package_name] = package_version
                break
            else:
                version_list = re.findall(r'class="vbtn release">(.+?)</a>', resp.text)
                if version_list:
                    for version_item in version_list:
                        if version_item.startswith(current_package_version):
                            package_version["same_version"] = version_item
                            break

                    package_version["last_version"] = version_list[0]
                    fix_version[package_name] = package_version
                    break

    return package_version


def sync_data(imageId=None, force=False):
    try:
        mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
        all_images = mongo_anchore_result.find({}, {"imageId": 1, "created_at": 1}, sort=[('created_at', -1)])

        resp_summaries = req(ANCHORE_API + "/summaries/imagetags", ANCHORE_USERNAME, ANCHORE_PASSWORD)

        if resp_summaries:
            if imageId:
                for resp_dict in resp_summaries:
                    if resp_dict["imageId"] == imageId:
                        resp_summaries = [resp_dict]
                        break
                else:
                    return True
            else:

                resp_summaries.sort(key=lambda x: x["created_at"], reverse=True)
                if all_images.count() and  resp_summaries[0]["created_at"] == all_images[0]["created_at"]:
                    resp_summaries = []
            all_images_id = map(lambda x: x["imageId"], all_images)
            for image in resp_summaries:
                if image["imageId"] not in all_images_id or force == True:
                    risk = {
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0
                    }
                    affected_package_count = set()

                    image["project_name"] = image['fulltag'][
                                            image['fulltag'].rfind("/") + 1:image['fulltag'].rfind(":")]

                    if image["analysis_status"] == "analyzed":
                        log.info("正在同步:%s" % image["imageId"])
                        resp_vlun = req(ANCHORE_API + "/images/by_id/" + image["imageId"] + "/vuln/all",
                                        ANCHORE_USERNAME, ANCHORE_PASSWORD)
                        if resp_vlun:

                            dependency_list = []
                            image["publisher"] = ""
                            resp_dependency = req(
                                GET_DEPENDENCY_API + "/dependency/result/?docker_url=" + image['fulltag'])

                            if resp_dependency:
                                dependency_result = base64.b64decode(resp_dependency["result"])
                                dependency_list = get_parents(dependency_result)
                                image["publisher"] = resp_dependency["publisher"]

                            for vlun_item in resp_vlun['vulnerabilities']:
                                affected_package_count.add(vlun_item['package_name'])

                                if vlun_item["package_type"] == "java":
                                    package_name = vlun_item["package_path"][
                                                   vlun_item["package_path"].rfind('/') + 1:]
                                    package_name = re.findall(r'(.+)-\d+\.', package_name)
                                    if len(package_name):
                                        package_name = package_name[0]
                                    else:
                                        package_name = re.sub(r'-\d+|\.\d+|\.jar', "", package_name)

                                else:
                                    package_name = vlun_item["package_name"]
                                vlun_item["package_name"] = package_name

                                if vlun_item['severity'] == "Critical":
                                    risk['critical'] += 1
                                elif vlun_item['severity'] == "High":
                                    risk['high'] += 1
                                elif vlun_item['severity'] == "Medium":
                                    risk['medium'] += 1
                                elif vlun_item['severity'] == "Low":
                                    risk['low'] += 1

                                for k in dependency_list:
                                    if vlun_item["package_name"] in k["child"]:
                                        vlun_item["parents"] = k["parents"]
                                        vlun_item["group_id"] = k["group_id"]

                                if vlun_item["fix"] == "None":

                                    if dependency_list:  # 存在依赖列表，有的项目不是用mvn的，所以没有
                                        try:
                                            if vlun_item["package_type"] == "java":  # get_version只支持java

                                                package_version = get_version(vlun_item["group_id"],
                                                                              vlun_item["parents"],
                                                                              image["imageId"])
                                                vlun_item["fix"] = package_version["last_version"]
                                                vlun_item["second_fix_version"] = package_version["same_version"]

                                            elif vlun_item["package_type"] == "python":
                                                pass

                                            else:
                                                log.warning(
                                                    "[%s][%s]包类型未处理：%s" % (
                                                        vlun_item["package"], vlun_item["package_type"],
                                                        image["imageId"]))
                                                vlun_item["fix"] = ""
                                                vlun_item["second_fix_version"] = ""
                                        except Exception, e:
                                            log.exception(
                                                "获取版本出错：【%s】%s" % (vlun_item["package"], image["imageId"]))
                                            vlun_item["fix"] = ""
                                            vlun_item["second_fix_version"] = ""

                            image["affected_package_count"] = len(affected_package_count)

                            image["vulnerabilities"] = resp_vlun["vulnerabilities"]

                            image["risk"] = risk

                    elif image["analysis_status"] == "analysis_failed":
                        image["vulnerabilities"] = []
                        image["affected_package_count"] = 0
                        image["risk"] = risk
                    else:
                        log.info("【扫描中的任务】created_at=%s,fulltag=%s" % (
                            timestamp2str(image["created_at"]), image["fulltag"]))

                    if image["analysis_status"] == "analyzed" or image["analysis_status"] == "analysis_failed":
                        log.info("添加镜像：%s" % image["imageId"])
                        mongo_anchore_result.update_many({"imageId": image["imageId"]}, {"$set": image}, upsert=True)


        return True
    except:
        log.exception("同步数据出错")
    return False


if __name__ == '__main__':
    sync_data("9f55d67f883db748711d661a477f714ce330eccf303710c3ddc0fdbca1e39e1a")
    # get_version("spring-boot-starter-validation:1.5.9.RELEASE")
