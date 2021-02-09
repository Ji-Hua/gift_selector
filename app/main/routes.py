from flask import render_template


from app import login
from flask_login import current_user, login_user, logout_user, login_required
from app.main import bp
from app.forms import LoginForm

@bp.route('/', methods=['GET', 'POST'])
@bp.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html', title='首页')


# TODO: add logging and email
@bp.app_errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@bp.app_errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500
