import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from flask import Flask, redirect, url_for, render_template, request
from flask_login import LoginManager
from flask_login import login_required, current_user

from auth import auth as auth_blueprint
from auth import constants, db, User

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.secret_key = SECRET_KEY
app.register_blueprint(auth_blueprint)

app.config['SQLALCHEMY_DATABASE_URI'] = constants['DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    view_groups = {"VoIP": "Телефоны", "MFU": "Принтеры", "Camera": "Камеры"}
    if request.method == 'POST':
        mac_address = request.form.get('mac').upper()
        group = request.form.get('groups')
        err_result = f'Результат:\n {current_user.username}, MAC адрес {mac_address} не добавлен. \n Причина: ' \
                     f'Проблемы на стороне сервера или ISE. '
        try:
            group_id = get_endpointgroup_by_name(group)
            status_code = append_mac_to_endpointgroup(mac_address, group_id, current_user.username, description)
            if status_code == 200 or status_code == 201:
                result = f'Результат:\n {current_user.username}, MAC адрес: {mac_address} успешно добавлен в группу {group}.'
            else:
                result = err_result
        except:
            result = err_result
        return render_template('index.html', groups=view_groups, result=result)
    else:
        if not current_user or current_user.is_anonymous:
            return redirect(url_for('auth.login'))
        return render_template('index.html', groups=view_groups)


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
server = constants['ISE_URLS']
ers_login = constants['ISE_USER']
ers_passwd = constants['ISE_PASS']
endpoint_groups = constants['ENDPOINT_GROUPS']


def check_endpoint_if_exist(mac_addr):
    check_endpoint_url = f'{server}endpoint/name/{mac_addr}'
    resp = requests.get(check_endpoint_url, headers=headers, auth=(ers_login, ers_passwd), verify=False)
    if resp.status_code == 200:
        return resp.json()['ERSEndPoint']['id']
    return None


def get_endpointgroup_by_name(name):
    get_endpointgroup_url = f'{server}endpointgroup/name/{name}'
    resp = requests.get(get_endpointgroup_url, headers=headers, auth=(ers_login, ers_passwd), verify=False)
    if resp.status_code == 200:
        return resp.json()['EndPointGroup']['id']
    return None


def append_mac_to_endpointgroup(mac_addr, group_id, username, description):
    endpoint_id = check_endpoint_if_exist(mac_addr)
    current_time = datetime.now().strftime("%d.%m.%y %H:%M:%S")
    data = {"ERSEndPoint": {"name": mac_addr, "mac": mac_addr, "staticGroupAssignment": True, "groupId": group_id, "description": f"{username}; {current_time}; {description}"}}
    if endpoint_id:
        update_url = f'{server}endpoint/{endpoint_id}'
        resp = requests.put(update_url, auth=(ers_login, ers_passwd), verify=False, json=data, headers=headers)
    else:
        add_url = f'{server}endpoint/'
        resp = requests.post(add_url, auth=(ers_login, ers_passwd), verify=False, json=data, headers=headers)
    return resp.status_code


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
