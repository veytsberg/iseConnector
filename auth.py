from flask import Blueprint
from flask import render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from ldap3 import Server, Connection, ALL
import json

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
    print(users)
    return render_template('login.html')


@auth.route('/login', methods=["POST"])
def login_post():
    username = request.form.get('email')
    passwd = request.form.get('password')
    remember = True if request.form.get('remember') else False

    s = Server(constants["LDAP_SERVER"], port=636, use_ssl=True, get_info=ALL)
    c = Connection(s, user=username, password=passwd)
    user = User(username) if c.bind() == True else None  # check user's credentials
    c.unbind()  # ends the user’s session and close the socket

    if user is None:
        flash('Please check your login details and try again.')
        return render_template('login.html')
    users[hash(user.username)] = user
    login_user(user, remember=remember)
    print(remember)
    return redirect(url_for('index'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
