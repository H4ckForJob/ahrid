#-*- coding:utf-8 -*-

'''
@Author: Vulkey_Chen
@Blog: gh0st.cn
@Team: Mystery Security Team
'''
import json

import requests
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from math import cos, sin, atan2, sqrt, radians, degrees
import hashlib, geoip2.database

db = SQLAlchemy()

def generate_password(rawpwd):
    m = hashlib.md5()
    m.update(rawpwd)
    return m.hexdigest()

def json_data(success, message, url=None):
    return jsonify(success=success, message=message, url=url)

def check_referer(request,uri):
    referer_http = "http://" + request.headers.get('Host') + uri
    referer_https = "https://" + request.headers.get('Host') + uri
    if request.referrer == referer_http or request.referrer == referer_https:
        return True
    else:
        return json_data(0, "非法的Referer来源头！")

def check_ip2country(ip):
    reader = geoip2.database.Reader('extender/GeoLite2-City.mmdb')
    c = reader.city(ip)
    en_name = c.country.name
    cn_name = c.country.names['zh-CN']

    if en_name == 'China':
        return en_name, cn_name, c.subdivisions.most_specific.names['zh-CN'] + c.city.names['zh-CN']
    else:
        return en_name, cn_name, None

def ip_into_int(ip):
    return reduce(lambda x,y:(x<<8)+y,map(int,ip.split('.')))

def is_internal_ip(ip):
    ip = ip_into_int(ip)
    net_a = ip_into_int('10.255.255.255') >> 24
    net_b = ip_into_int('172.31.255.255') >> 20
    net_c = ip_into_int('192.168.255.255') >> 16
    return ip >> 24 == net_a or ip >>20 == net_b or ip >> 16 == net_c

def center_geolocation(geolocations):
    x = 0
    y = 0
    z = 0
    length = len(geolocations)
    for lon, lat in geolocations:
        lon = radians(float(lon))
        lat = radians(float(lat))
        x += cos(lat) * cos(lon)
        y += cos(lat) * sin(lon)
        z += sin(lat)
    x = float(x / length)
    y = float(y / length)
    z = float(z / length)
    return (degrees(atan2(y, x)), degrees(atan2(z, sqrt(x * x + y * y))))

def get_xy(ip,tx_key,jd_key):
    tx_api = "https://apis.map.qq.com/ws/location/v1/ip?ip={0}&key={1}".format(ip,tx_key)
    jd_api = "https://way.jd.com/RTBAsia/ip_location?ip={0}&appkey={1}".format(ip,jd_key)

    t = requests.get(tx_api)
    j = requests.get(jd_api)

    try:
        tx_lng = json.loads(t.text)['result']['location']['lng']
        tx_lat = json.loads(t.text)['result']['location']['lat']
    except:
        tx_lng = None
        tx_lat = None

    try:
        jd_lng = json.loads(j.text)['result']['location']['longitude']
        jd_lat = json.loads(j.text)['result']['location']['latitude']
    except:
        jd_lng = None
        jd_lat = None

    tx = (tx_lng, tx_lat)
    jd = (jd_lng, jd_lat)
    xys = [tx, jd]
    try:
        center = center_geolocation(xys)
    except:
        center = None
    return xys,center

def get_address(x,y,tx_key):
    url = 'https://apis.map.qq.com/ws/geocoder/v1/?location={0},{1}&key={2}'.format(x,y,tx_key)
    r = requests.get(url)
    return json.loads(r.text)['result']['address']
