#-*- coding:utf-8 -*-

'''
@Author: Vulkey_Chen
@Blog: gh0st.cn
@Team: Mystery Security Team
'''

from exts import db,generate_password
import datetime

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(32), nullable=False)

    def __init__(self,*args,**kwargs):
        username = kwargs.get('username')
        password = generate_password(kwargs.get('password'))
        self.username = username
        self.password = password

    def check_password(self,raw_password):
        if generate_password(raw_password) == self.password:
            return True
        else:
            return False

class Hackinfo(db.Model):
    __tablename__ = 'hackinfo'
    hid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(15), nullable=False)
    user_agent = db.Column(db.Text, nullable=False)
    jsondata = db.Column(db.Text, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.datetime.now)
    times = db.Column(db.Integer, nullable=False, default=1)
    __mapper_args__ = {
        'order_by': create_time.desc()
    }

class Plugins(db.Model):
    __tablename__ = 'plugins'
    pid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    src = db.Column(db.Text, nullable=False)
    callback = db.Column(db.String(100), nullable=False)
    columns = db.Column(db.Text, nullable=False)
    url = db.Column(db.Text, nullable=True, default=None)
    commit = db.Column(db.Text, nullable=False)

class Apis(db.Model):
    __tablename__ = 'apis'
    aid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host = db.Column(db.Text, nullable=False)