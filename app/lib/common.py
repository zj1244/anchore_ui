# !/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import base64
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

import time
import re, sys, random
import requests
from config import *
from app import mongo, apscheduler, log

reload(sys)
sys.setdefaultencoding('utf8')

fix_version = {

}

poc = {

}


def timestamp2str(date):
    if date:

        return datetime.fromtimestamp(date).strftime("%Y-%m-%d %H:%M:%S")
    else:
        return ""


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def get_header():
    header = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Accept-Encoding': 'gzip, deflate'
    }
    log.info("header=" + str(header))
    return header


def dict2str(dictionary):
    try:
        if type(dictionary) == str:
            return dictionary
        return json.dumps(dictionary)
    except TypeError as e:
        log.exception("conv dict failed : %s" % e)


def req(url, user="", pwd=""):
    resp_json = {}

    try:
        if user and pwd:
            session = requests.session()
            session.auth = (user, pwd)

            resp = session.get(url, headers={'Connection': 'close'})

            if resp.status_code == 200:
                resp_json = resp.json()
        else:
            resp = requests.get(url=url)
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

        mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
        images = mongo_anchore_result.find({"project_name": project_name}).sort("created_at", -1).limit(n)

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

                log.exception(i)
    return final_result


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
        parents_jar = ""
        parents_jar_name=""
        match_obj = re.findall(r"- (.+):(.+):(.+):(.+):(.+)", dependency)
        if match_obj:
            parents_jar = ":".join([match_obj[0][0], match_obj[0][1], match_obj[0][3]])
            parents_jar_name=match_obj[0][1]
            for i in range(1, len(match_obj)):
                child_jar.append(match_obj[i][1])


        if len(child_jar) == 0:
            child_jar = [parents_jar_name]
        else:
            child_jar.append(match_obj[0][1])

        ouput.append({"parents": parents_jar, "child": child_jar})
    return ouput


def format_version(version, point):
    k = 0

    version_list = list(version)
    for i in range(len(version_list)):
        if version_list[i] == ".":
            k += 1
        if k == point:
            return version[:i + 1]
    return ""


def get_version(package, image_id):
    package_version = {
        "last_version": "",
        "second_version": ""
    }
    group_id, package_name, current_package_version = package.split(":")
    if current_package_version.count(".") in [2, 3]:  # 8.0.28 or 2.2.2.RELEASE
        current_package_version = format_version(current_package_version, 2)
    elif current_package_version.count("-") == 1:
        current_package_version = current_package_version[:current_package_version.find("-")]
    else:
        log.info("未处理的版本号:%s image_id=%s" % (package, image_id))

    if fix_version.has_key(package_name):
        print "找到%s的版本是%s" % (package_name, fix_version[package_name])
        package_version = fix_version[package_name]
    else:
        # 如果是返回码不是200就死循环去获取，200就跳出
        while True:

            url = "https://mvnrepository.com/artifact/%s/%s" % (group_id, package_name)
            session = requests.Session()
            retry = Retry(connect=3, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            resp = session.get(url=url, verify=False, headers=get_header())
            if resp.status_code == 403:
                log.info("查找包异常，status=%s" % resp.status_code)
                time.sleep(5)
            elif resp.status_code == 404:
                fix_version[package_name] = package_version
                break
            else:
                version_list = re.findall(r'class="vbtn release">(.+?)</a>', resp.text)
                if version_list:
                    # print "添加一个包%s到内存%s" % (package_name, version_list[0])
                    for version_item in version_list:
                        if version_item.startswith(current_package_version):
                            package_version["second_version"] = version_item
                            break

                    package_version["last_version"] = version_list[0]
                    fix_version[package_name] = package_version
                    break


    return package_version


def sync_data(imageId=None):
    try:
        mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
        images_num = mongo_anchore_result.find_one({}, sort=[('created_at', -1)])

        resp_summaries = req(ANCHORE_API + "/summaries/imagetags", USERNAME, PASSWORD)
        log.info(len(resp_summaries))
        if resp_summaries:
            if imageId:
                for resp_dict in resp_summaries:
                    if resp_dict["imageId"] == imageId:
                        resp_summaries = [resp_dict]
                        break
            else:

                resp_summaries.sort(key=lambda x: x["created_at"], reverse=True)
                if resp_summaries[0]["created_at"] == images_num["created_at"]:
                    resp_summaries = []
            for image in resp_summaries:

                if mongo_anchore_result.find({"imageId": image["imageId"]}).count() == 0:
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
                        log.info("正在处理%s" % image["imageId"])
                        resp_vlun = req(ANCHORE_API + "/images/by_id/" + image["imageId"] + "/vuln/all",
                                        USERNAME, PASSWORD)
                        if resp_vlun:

                            dependency_list = []
                            image["publisher"] = ""
                            resp_dependency = req(
                                GET_DEPENDENCY_API + "/dependency/result/?docker_url=" + image['fulltag'])

                            if resp_dependency and resp_dependency["code"] == 200:
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

                                if vlun_item["fix"] == "None":

                                    if dependency_list:  # 存在依赖列表，有的项目不是用mvn的，所以没有
                                        try:
                                            if vlun_item["package_type"] == "java":  # get_version只支持java

                                                package_version = get_version(vlun_item["parents"],
                                                                              image["imageId"])
                                                vlun_item["fix"] = package_version["last_version"]
                                                vlun_item["second_fix_version"] = package_version["second_version"]

                                            elif vlun_item["package_type"] == "python":
                                                pass

                                            else:
                                                log.warning(
                                                    "【%s】包类型未处理：%s" % (vlun_item["package"], image["imageId"]))
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
                        mongo_anchore_result.insert_one(image)
        return True
    except:
        log.exception("同步数据出错")
    return False


if __name__ == '__main__':
    sync_data("6fdf5b6407344e45c469e0364f69fc744f40407a5fa28f18269fc819cb2bef6e")
    # get_version("spring-boot-starter-validation:1.5.9.RELEASE")
