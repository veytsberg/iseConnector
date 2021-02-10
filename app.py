from flask import Flask, redirect, url_for, render_template
from flask_login import LoginManager
from flask_login import login_required, current_user
from auth import users
from auth import auth as auth_blueprint
import os, requests

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.secret_key = SECRET_KEY
app.register_blueprint(auth_blueprint)

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)


@app.route('/')
@login_required
def index():
    print(current_user)
    if not current_user or current_user.is_anonymous:
        return redirect(url_for('auth.login'))
    groups = ['Телефон', 'Принтер', 'Камера']
    return render_template('index.html', name=current_user.username, groups=groups)


@login_manager.user_loader
def load_user(id):
    if id in users:
        return users[id]
    return None


def check_endpoint_if_exist():
    pass


def get_endpointgroup_by_name():
    pass


def append_mac_to_endpointgroup():
    if check_endpoint_if_exist():
        # put
        return
    # post
    return


if __name__ == "__main__":
    app.run(debug=True)
