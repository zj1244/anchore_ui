FROM ubuntu:14.04
MAINTAINER zj1244
ENV LC_ALL C.UTF-8
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN set -x \
    && apt-get update \
    && apt-get install python-pip python-dev -y \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/anchore_ui
COPY . /opt/anchore_ui

RUN set -x \
    && pip install -r /opt/anchore_ui/requirements.txt \
    && cp /opt/anchore_ui/config.py.sample /opt/anchore_ui/config.py

WORKDIR /opt/anchore_ui
ENTRYPOINT ["python","run.py"]
CMD ["/usr/bin/tail", "-f", "/dev/null"]