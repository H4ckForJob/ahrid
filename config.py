#-*- coding:utf-8 -*-

'''
@Author: Vulkey_Chen
@Blog: gh0st.cn
@Team: Mystery Security Team
'''

import random

DIALECT = 'mysql'
DRIVER = 'mysqldb'
USERNAME = ''
PASSWORD = ''
HOST = ''
PORT = ''
DATABASE = 'ahrid'
SQLALCHEMY_DATABASE_URI = '{}+{}://{}:{}@{}:{}/{}?charset=utf8'.format(DIALECT,DRIVER,USERNAME,PASSWORD,HOST,PORT,DATABASE)
SQLALCHEMY_TRACK_MODIFICATIONS = False

SECRET_KEY = ""


TX_KEYS = ["",""]

JCLOUD_KEY = ""

TX_KEY = TX_KEYS[random.randint(0,len(TX_KEYS)-1)]