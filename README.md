# Anchore_ui

## 介绍

**Anchore_ui**是一款用于展示Anchore Engine扫描结果的web系统。

## 支持平台

* Linux
* Windows

## 安装指南

[![Python 2.7](https://img.shields.io/badge/python-2.7-yellow.svg)](https://www.python.org/) 
[![Mongodb 3.x](https://img.shields.io/badge/mongodb-3.x-red.svg)](https://www.mongodb.com/download-center?jmp=nav)

### 源码部署

**依赖：项目运行依赖于mongodb，所以需准备好mongodb

***

**源码部署**步骤如下：


#### 1. 添加mongodb认证

**在 mongodb 服务器上**新建 db 用户，这里新建了一个用户名为`anchore_ui`密码为`123456`的用户。

```
# mongo
> use admin
> db.createUser({user:'anchore_ui',pwd:'123456', roles:[{role:'readWriteAnyDatabase', db:'admin'}]})
> exit
```

#### 2. 安装python依赖库

```
# git clone https://github.com/zj1244/anchore_ui.git
# cd anchore_ui
# pip install -r requirements.txt
```

#### 3. 修改配置文件

首先将`config.py.sample`复制一份重命名为`config.py`
```
# cp anchore_ui/config.py.sample anchore_ui/config.py
```

然后修改config.py里的配置信息：

```
# 按照实际情况mongodb的相关配置
MONGO_IP = "192.168.47.1"
MONGO_PORT = 27017
MONGO_USER = "root"
MONGO_PWD = "root"
# 按照实际情况修改anchore的相关配置
ANCHORE_API = "http://192.168.1.1:8228"
ANCHORE_USERNAME = "admin"
PASSWORD = "foobar"
```

#### 4. 启动

在程序目录下执行如下命令：

```
# python run.py
```

### 容器化部署

推荐使用外部mongodb来进行存储

#### 1. 构建镜像

新建个docker-compose.yml文件，复制粘贴如下内容，并根据实际情况修改mongo配置信息：

```

```
