#-*- coding:utf-8 -*-

'''
@Author: Vulkey_Chen
@Blog: gh0st.cn
@Team: Mystery Security Team
'''

from flask_script import Manager
from flask_migrate import Migrate,MigrateCommand
from app import app
from exts import db

manager = Manager(app)
migrate = Migrate(app,db)
manager.add_command('db',MigrateCommand)

if __name__ == '__main__':
    manager.run()