import json
import re
from ldap3 import Server, Connection, ALL
from flask import Blueprint
from flask import render_template, redirect, url_for, request, flash
from flask_login import UserMixin, login_required, login_user, logout_user


auth = Blueprint('auth', __name__)

users = {}

with open('constants.json') as json_file:
    constants = json.load(json_file)


class User(UserMixin):
    def __init__(self, username):
        self.id = hash(username)
        self.username = username

    def __repr__(self):
        return self.username

    def get_id(self):
        return self.id


@auth.route('/login')
def login():
    return render_template('login.html', auth_result='')


@auth.route('/login', methods=["POST"])
def login_post():
    username = request.form.get('email')
    passwd = request.form.get('password')
    user = None
    s = Server(constants["LDAP_SERVER"], port=constants["LDAP_PORT"], use_ssl=True, get_info=ALL)
    c = Connection(s, user=username, password=passwd)
    c.bind()
    login_without_domain = re.findall(r'^[\w\d]+', username)[0]

    # check user's credentials
    if c.result['description'] == 'success':
        search_res = c.search(f'ou=sites,dc={constants["DOMAIN"]}', f"(&(objectClass=person)(sAMAccountName={login_without_domain}))")
        if search_res:
            dn = c.entries[0].entry_dn
            user = User(username) if re.search(constants["AD_GROUP"], dn) else None
    c.unbind()  # ends the user’s session and close the socket

    if user is None:
        return render_template('login.html', auth_result='Неверные данные.')
    users[hash(user.username)] = user
    login_user(user)
    return redirect(url_for('index'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
