import os
import sys
import json
import time
import logging

from hashlib import sha256

from flask import request, current_app, redirect, url_for, Flask
from functools import wraps
from Crypto.Cipher import AES

app = Flask(__name__)
key = os.urandom(16)

AUTH = 'auth'

def nonce():
    return sha256(str(int(time.time()))).digest()[:8]

def make_cookie():
    pt = json.dumps({'id': os.urandom(16).encode('hex'), 'admin': 0})
    no = nonce()
    cf = AES.new(
        key,
        mode=AES.MODE_GCM,
        nonce=no
    )
    ct = no + cf.encrypt(pt)
    return ct.encode('hex')

def load_cookie(ct):
    ct = ct.decode('hex')
    cf = AES.new(
        key,
        mode=AES.MODE_GCM,
        nonce=ct[:8]
    )
    pt = cf.decrypt(ct[8:])
    return json.loads(pt)

def login_required(admin):
    def decor(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if AUTH not in request.cookies:
                app.logger.info('no cookie')
                response = current_app.make_response(redirect('/'))
                response.set_cookie(AUTH, value=make_cookie())
                return response

            try:
                cook = load_cookie(request.cookies[AUTH])
                app.logger.info('valid cookie: ' + str(cook))
                if admin and not cook['admin']:
                    return redirect('/')

            except:
                app.logger.info('invalid cookie :(')
                response = current_app.make_response(redirect('/'))
                response.set_cookie(AUTH, value=make_cookie())
                return response

            return f(*args, **kwargs)
        return decorated_function
    return decor

@app.route('/')
@app.route('/index')
@login_required(admin = False)
def index_page():
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return 'Time is flying: <b>%s</b>' % t

@app.route('/admin')
@login_required(admin = True)
def admin_page():
    with open('flag', 'r') as f:
        return f.read()

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)
app.run(debug=False)
