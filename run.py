#!/usr/bin/env python
# coding: utf-8
from config import WEB_IP,WEB_PORT
from apps.views import app,apscheduler


if __name__ == '__main__':
    apscheduler.init_app(app)
    # apscheduler._logger = Log("run.log")
    apscheduler.start()

    app.run(use_reloader=False, threaded=True, port=WEB_PORT, host=WEB_IP, debug=True)
