import json
import re
from ldap3 import Server, Connection, ALL
from flask import Blueprint
from flask import render_template, redirect, url_for, request
from flask_login import UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy

auth = Blueprint('auth', __name__)
db = SQLAlchemy()

with open('constants.json', encoding='utf8') as json_file:
    constants = json.load(json_file)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)

    def __init__(self, username):
        self.username = username

    @staticmethod
    def try_login(username, passwd):
        domain = constants["DOMAIN"]
        s = Server(constants["LDAP_SERVER"], port=constants["LDAP_PORT"], use_ssl=True, get_info=ALL)
        c = Connection(s, user=f'{username}@{domain}', password=passwd)
        c.bind()
        if c.result['description'] == 'success':
            search_res = c.search(f'ou=sites,dc={domain}',
                                  f"(&(objectClass=person)(sAMAccountName={username}))")
            if search_res:
                dn = c.entries[0].entry_dn
                if re.search(constants["AD_GROUP"], dn):
                    return True
        c.unbind()  # ends the user’s session and close the socket
        return False


@auth.route('/login')
def login():
    return render_template('login.html', auth_result='')


@auth.route('/login', methods=["POST"])
def login_post():
    username = request.form.get('username')
    passwd = request.form.get('password')

    if not User.try_login(username, passwd):
        return render_template('login.html', auth_result='Неверные данные.')

    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username)
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for('index'))


@auth.route('/logout')
@login_required
def logout():
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))
