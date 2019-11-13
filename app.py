#-*- coding:utf-8 -*-

'''
@Author: Vulkey_Chen
@Blog: gh0st.cn
@Team: Mystery Security Team
'''

import json
import re
import config


from base64 import b64decode, b64encode
from flask import Flask, render_template, session, g, request, redirect, url_for
from gevent import pywsgi
from gevent import monkey
from exts import db, generate_password, json_data, check_referer, is_internal_ip, check_ip2country, get_xy, get_address
from decorators import login_required
from models import Admin, Hackinfo, Plugins, Apis

monkey.patch_all()

app = Flask(__name__)
app.config.from_object(config)
db.init_app(app)

# login
@app.route('/login')
def login_page():
    if session.get('user_id'):
        return redirect(url_for('index_page'))
    else:
        return render_template('login.html')

@app.route('/dologin', methods=['POST'])
def login():
    # 登录
    username = request.form.get('username')
    password = request.form.get('password')
    admin = Admin.query.filter(Admin.username == username).first()
    if admin:
        if admin.check_password(password):
            session['user_id'] = admin.id
            session.permanent = True
            return json_data(1, "用户登陆成功！", url_for('index_page'))
        else:
            return json_data(0, "用户密码错误！")
    else:
        return json_data(0, "用户名不存在！")

# logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# index
@app.route('/')
@login_required
def index_page():
    hackinfo = Hackinfo.query.order_by(Hackinfo.times.desc()).all()
    website = Hackinfo.query.with_entities(Hackinfo.host).distinct().all()
    admin = Admin.query.all()
    plugin = Plugins.query.all()
    content = {
        'hackinfo':hackinfo[0:10],
        'user_count': len(admin),
        'attacker_count': len(hackinfo),
        'plugin_count': len(plugin),
        'website_count': len(website)
    }
    return render_template('index.html', **content)

# get country
@app.route('/country', methods=['POST'])
@login_required
def get_country():
    ip = request.form.get('ip')
    if not is_internal_ip(ip):
        try:
            en, cn, city = check_ip2country(ip)
            if en != "China":
                return json_data(1, message=cn)
        except:
            return json_data(0, message="None")
    return json_data(1, message="<img src='{0}' style='height: 30px; width: 30px'>".format(url_for('static', filename='images/flags/china.png')))

# setting
@app.route('/setting')
@login_required
def setting_page():
    admin = Admin.query.all()
    return render_template('setting.html',user=admin)

@app.route('/user/add', methods=['POST'])
@login_required
def add_user():
    # 添加用户
    referer = check_referer(request, url_for('setting_page'))
    if referer == True:
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter(Admin.username == username).first()
        # username check
        if (not admin) and (len(username) < 20):
            user = Admin(username=username,password=password)
            db.session.add(user)
            db.session.commit()
            return json_data(1, message="用户创建成功！", url=url_for('setting_page'))
        else:
            return json_data(0, message="用户名已经存在或超出20长度！")
    else:
        return referer

@app.route('/user/del/<uid>', methods=['POST'])
@login_required
def del_user(uid):
    # 删除用户
    referer = check_referer(request, url_for('setting_page'))
    if referer == True:
        user = Admin.query.filter(Admin.id == uid).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return json_data(1, message="用户删除成功！", url=url_for('setting_page'))
        else:
            return json_data(0, message="用户名不存在！")
    else:
        return referer

# attackers
@app.route('/attackers')
@login_required
def attacker_page():
    hackinfo = Hackinfo.query.all()
    return render_template('attack.html', attackers=hackinfo)

@app.route('/attackers/<hid>')
@login_required
def attacker_detail(hid):
    # 攻击者详细信息
    attacker = Hackinfo.query.filter(Hackinfo.hid == hid).first()
    if attacker:
        ip = attacker.ip

        try:
            # 根据IP地址获取城市位置
            en, cn, city = check_ip2country(ip)
        except:
            city = None

        content = {
            'attacker': attacker,
            'hackinfo': json.loads(attacker.jsondata),
            'xy': get_xy(ip,config.TX_KEY,config.JCLOUD_KEY),
            'city': city
        }
        return render_template('attack_details.html', **content)
    else:
        return redirect(url_for('attacker_page'))

# maps
@app.route('/maps')
@login_required
def maps():
    # 地图
    return render_template('maps.html')

@app.route('/locations', methods=['POST'])
@login_required
def locations():
    # 获取详细地址
    lat = request.form.get('lat')
    lng = request.form.get('lng')
    try:
        address = get_address(lat, lng, config.TX_KEY)
        return json_data(1, message=address)
    except:
        return json_data(0, message=None)

# apis
@app.route('/apis')
@login_required
def api_page():
    # 接口授权
    apis = Apis.query.all()
    return render_template('api.html', apis=apis)


@app.route('/apis/del/<aid>', methods=['POST'])
@login_required
def del_api(aid):
    # 删除授权
    referer = check_referer(request, url_for('api_page'))
    if referer == True:
        apis = Apis.query.filter(Apis.aid == aid).first()
        if apis:
            db.session.delete(apis)
            db.session.commit()
            return json_data(1, message="该授权已经删除！", url=url_for('api_page'))
        else:
            return json_data(0, message="该授权不存在！")
    else:
        return referer

@app.route('/apis/add', methods=['POST'])
@login_required
def add_api():
    # 增加授权
    referer = check_referer(request, url_for('api_page'))
    if referer == True:
        host = request.form.get('host')
        # 判断是否是域名
        host_regex = r"^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})(:{0,1}[0-9]{0,5})+$"
        host_result = re.findall(host_regex, host)
        # 判断是否是IP
        ip_regex = r"^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$"
        ip_result = re.findall(ip_regex, host)
        if host_result != [] or ip_result != []:
            apis = Apis.query.filter(Apis.host == host).first()
            if apis:
                return json_data(0, message="该授权已存在！")
            else:
                apis = Apis(host=host)
                db.session.add(apis)
                db.session.commit()
                return json_data(1, message="授权已添加成功！", url=url_for('api_page'))
        else:
            return json_data(0, message="这不是一个正确的域名或IP！")
    else:
        return referer

# plugins
@app.route('/plugins')
@login_required
def plugin_page():
    plugins = Plugins.query.all()
    return render_template('plugins.html', plugins = plugins)

@app.route('/plugins/<pid>')
@login_required
def plugins_detail(pid):
    # 插件详细
    plugin = Plugins.query.filter(Plugins.pid == pid).first()
    if plugin:
        return render_template('plugins_detail.html', plugin=plugin)
    else:
        return redirect(url_for('plugin_page'))

@app.route('/plugins/edit/<pid>', methods=['POST'])
@login_required
def edit_plugin(pid):
    # 编辑插件
    referer = check_referer(request, url_for('plugins_detail', pid=pid))
    if referer == True:
        plugin = Plugins.query.filter(Plugins.pid == pid).first()
        # 判断是否存在该插件
        if plugin:
            name = request.form.get("name")
            src = request.form.get("src")
            callback = request.form.get("callback")
            columns = request.form.get("columns")
            url = request.form.get("url")
            commit = request.form.get("commit")
            # 判断name和callback的长度
            if len(name) < 100 and len(callback) < 100:
                plugin.name = name
                plugin.src = src
                plugin.callback = callback
                plugin.columns = columns
                plugin.url = url
                plugin.commit = commit
                db.session.commit()
                return json_data(1, message="插件编辑成功！", url=url_for('plugins_detail', pid=pid))
            else:
                return json_data(0, message="Name或Callback字段大于长度100！")
        else:
            return redirect(url_for('plugin_page'))
    else:
        return referer

@app.route('/plugins/del/<pid>', methods=['POST'])
@login_required
def del_plugin(pid):
    # 删除模块
    referer = check_referer(request, url_for('plugin_page'))
    if referer == True:
        plugin = Plugins.query.filter(Plugins.pid == pid).first()
        # 判断是否存在该模块
        if plugin:
            db.session.delete(plugin)
            db.session.commit()
            return json_data(1, message="插件删除成功！", url=url_for('plugin_page'))
        else:
            return json_data(0, message="插件不存在！")
    else:
        return referer

@app.route('/plugins/add', methods=['POST'])
@login_required
def add_plugin():
    # 添加模块
    referer = check_referer(request, url_for('submit_plugin_page'))
    if referer == True:
        name = request.form.get("name")
        src = request.form.get("src")
        callback = request.form.get("callback")
        columns = request.form.get("columns")
        url = request.form.get("url")
        commit = request.form.get("commit")
        # 判断name和callback的长度是否大于100
        if len(name) < 100 and len(callback) < 100:
            plugin = Plugins(name=name, src=src, callback=callback, columns=columns, url=url, commit=commit)
            db.session.add(plugin)
            db.session.commit()
            return json_data(1, message="插件添加成功！", url=url_for('plugin_page'))
        else:
            return json_data(0, message="Name或Callback字段大于长度100！")
    else:
        return referer


@app.route('/plugin/submit')
@login_required
def submit_plugin_page():
    return render_template('plugins_submit.html')

# profile
@app.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html', user=g.user, loginip=request.remote_addr)

@app.route('/mofidy', methods=['POST'])
@login_required
def mofidy_pwd():
    # 修改密码
    old_password = request.form.get('oldpassword')
    new_password = request.form.get('newpassword')
    # 查询
    admin = Admin.query.filter(Admin.id == g.user.id).first()
    # 判断old_password是否与原密码一致 and 判断old_password是否和new_password一致
    if admin.check_password(old_password) and (old_password != new_password):
        admin.password = generate_password(new_password)
        db.session.commit()
        session.clear()
        return json_data(1, message="密码修改成功，请重新登陆！", url=url_for("login_page"))
    else:
        return json_data(0, message="当前密码输入错误或当前密码与新密码相同！")


# import hackinfo
@app.route('/hackinfo/import', methods=['POST'])
def import_hackinfo():
    # 获取到的黑客数据信息
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")
    json_data = request.form.get('json_data')
    host = request.form.get('host')
    data = json.loads(b64decode(json_data))
    jdata = {}

    if data != {}:
        # 垃圾数据拦截
        for i in data.keys():
            fuckdata = Plugins.query.filter(Plugins.name == i).first()
            if fuckdata:
                jdata[i] = data[i]
            else:
                pass

    apis = Apis.query.filter(Apis.host == host).first()
    if apis and (jdata != {} or data == {}):
        # 导入黑客信息到数据库
        hackinfo = Hackinfo.query.filter(Hackinfo.ip == ip).first()
        if hackinfo:
            # 当发现黑客IP存在的时候就将其攻击次数+1
            hackinfo.times = int(hackinfo.times) + 1
            db.session.commit()
            return u"Building...."
        else:
            # 当黑客IP不存在时则添加入库
            if data != {}:
                attacker = Hackinfo(host=host, ip=ip, user_agent=ua, jsondata=json.dumps(jdata))
            else:
                attacker = Hackinfo(host=host, ip=ip, user_agent=ua, jsondata=None)
            db.session.add(attacker)
            db.session.commit()
            return u"Building...."
    else:
        return u"FUCK U!!!"

# generate javascript
@app.route('/jquery.min.js')
def generate_js():
    # 根据模块接口生成Javascript代码
    # 所需plugins的字段: src callback columns
    host = request.headers.get("Host")
    plugins = Plugins.query.all()
    p_length = len(plugins)
    js_code = render_template('plugins.js', plength=p_length, plugins=plugins, host=host)
    code = "eval(atob('" + b64encode(js_code) + "'));"
    return code , 200, {"Content-Type": "application/x-javascript; charset=utf-8"}

@app.before_request
def before_request():
    id = session.get('user_id')
    if id:
        user = Admin.query.get(id)
        # 判断用户是否真实存在
        if user:
            g.user = user
        else:
            session.clear()
            return redirect(url_for('login_page'))

@app.context_processor
def context_processor():
    if hasattr(g, 'user'):
        return {"user":g.user}
    else:
        return {}

if __name__ == '__main__':
    server = pywsgi.WSGIServer(('0.0.0.0', 80), app)
    server.serve_forever()