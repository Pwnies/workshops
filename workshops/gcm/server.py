import os
import sys
import json
import time
import logging

'''
requires:
    pycryptodome
    flask
'''

from hashlib import sha256

from flask import Flask
from flask import request
from flask import redirect
from flask import Response
from flask import current_app
from flask import url_for

from functools import wraps

from Crypto.Cipher import AES

app = Flask(__name__)
key = os.urandom(16)

## Authentication system ##

AUTH = 'auth'

def nonce():
    raw = sha256(str(int(time.time()))).digest()
    return raw[:8]

def gcm_encrypt(key, pt):
    iv = nonce()
    cf = AES.new(key, AES.MODE_GCM, iv)
    ct, tag = cf.encrypt_and_digest(pt)
    return iv + ct + tag

def gcm_decrypt(key, ct):
    iv  = ct[:8]
    tag = ct[-16:]
    ct  = ct[8:-16]
    cf  = AES.new(key, AES.MODE_GCM, iv)
    pt  = cf.decrypt_and_verify(ct, tag)
    return pt

def make_cookie():
    pt = json.dumps({
        'id': os.urandom(16).encode('hex'),
        'admin': 0
    })
    ct = gcm_encrypt(key, pt)
    return ct.encode('hex')

def load_cookie(ct):
    print ct
    pt = gcm_decrypt(
        key,
        ct.decode('hex')
    )
    print 'authenticity validated:', pt
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
                app.logger.info('invalid cookie')
                response = current_app.make_response(redirect('/'))
                response.set_cookie(AUTH, value=make_cookie())
                return response

            return f(*args, **kwargs)
        return decorated_function
    return decor

## Web app & handlers ##

@app.route('/')
@login_required(admin = False)
def code_page():
    with open(sys.argv[0], 'r') as f:
        return Response(f.read(), mimetype='text/plain')

@app.route('/time')
@login_required(admin = False)
def index_page():
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return 'Time is flying: <b>%s</b>' % t

@app.route('/flag')
@login_required(admin = True)
def admin_page():
    with open('flag', 'r') as f:
        return Response(f.read(), mimetype='text/plain')

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.INFO)
app.run(debug=False)
