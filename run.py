#!/usr/bin/env python
# coding: utf-8

from app.lib.common import *
from app.views import app


if __name__ == '__main__':
    apscheduler.init_app(app)
    # apscheduler._logger = Log("run.log")
    apscheduler.start()

    app.run(use_reloader=False, threaded=True, port=8888, host='0.0.0.0', debug=True)
