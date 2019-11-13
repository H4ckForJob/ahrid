#-*- coding:utf-8 -*-

'''
@Author: Vulkey_Chen
@Blog: gh0st.cn
@Team: Mystery Security Team
'''

from functools import wraps
import flask

def login_required(func):
    @wraps(func)
    def wrapper(*args,**kwargs):
        if hasattr(flask.g,'user'):
            return func(*args,**kwargs)
        else:
            return flask.redirect(flask.url_for('login_page'))
    return wrapper
