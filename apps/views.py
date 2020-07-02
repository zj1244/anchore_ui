# -*- coding: UTF-8 -*-
import sys

from json import dumps
from flask import request, render_template, redirect, url_for, session
from flask_wtf.csrf import CSRFError
from config import *
from . import app, csrf, apscheduler

from lib.login import login_check
from lib import common
from lib.scheduler import Scheduler
from lib.dependency import Dependency

reload(sys)
sys.setdefaultencoding('utf8')
scheduler = Scheduler()
dependency = Dependency()


@app.template_filter(name='unicode2str')
def unicode2str(data):
    convert = []
    for i in data:
        convert.append(str(i))
    return convert


# 镜像详情
@app.route('/images_details')
@app.route('/tmp_link')
def images_details():
    if request.path == "/images_details":
        if session.get('login', '') != 'login_success':
            return redirect(url_for('login'))

    total_risk = []
    total_package = []
    analysis_date = []

    image_id = request.args.get('image_id', '')

    resp = common.get_images_details(image_id)
    for k, v in resp['total_risk'].items():
        total_risk.append(
            {"name": str(k), "value": v}
        )
    total_risk.sort()
    for k, v in resp["total_package"].items():
        total_package.append(
            {"name": str(k), "value": v}
        )

    vuln_trend = common.get_vuln_trend(resp["project_name"])
    pom_file = common.get_pom_file(resp["fulltag"])
    if request.path == "/images_details":
        return render_template('images_details.html', vuln_trend=vuln_trend,
                               total_risk=total_risk, total_package=total_package, analysis_date=analysis_date,
                               resp=resp, image_id=image_id, pom_file=pom_file)
    else:
        return render_template('tmp_link.html', vuln_trend=vuln_trend,
                               total_risk=total_risk, total_package=total_package, analysis_date=analysis_date,
                               resp=resp, image_id=image_id, pom_file=pom_file)


# 分析页面
@app.route("/")
@app.route("/index")
@login_check
@csrf.exempt
def index():
    resp = common.get_project()
    return render_template('index.html', resp=resp)


@app.route('/login', methods=['get', 'post'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        if username == app.config.get('ACCOUNT') and password == app.config.get('PASSWORD'):
            session['login'] = 'login_success'
            return dumps({"status": "success", "content": "登陆成功", "redirect": url_for("index")})
        else:
            return dumps({"status": "error", "content": "密码错误"})


@app.route('/images_sync', methods=['get', 'post'])
@login_check
def images_sync():
    action = request.args.get('action', '')
    if action == "refresh":
        return dumps(scheduler.refresh())

    elif action == "add":
        if request.method == "GET":
            return render_template('add_sync.html')
        else:
            job_time = request.form.get('job_time', '')
            job_unit = request.form.get('job_unit', '')
            resp = scheduler.add(job_time, job_unit)
            return dumps(resp)

    elif action == "remove":
        return dumps(scheduler.remove())
    else:
        resp = scheduler.get()
        return render_template('images_sync.html', resp=resp["data"])


@app.route('/dependency/result/', methods=['GET', 'POST'], strict_slashes=False)
def dependency_result():

    if request.method == "POST":
        return dumps(dependency.save(request.get_json()))
    else:
        return dumps(dependency.get(request.args.get("docker_url", "")))


@app.route("/logout")
@login_check
def logout():
    session["login"] = ""
    return redirect(url_for("login"))


@app.errorhandler(500)
def handle_500(e):
    return render_template("500.html")


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return redirect(url_for("Error"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html")
