from urllib.parse import unquote

from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

from app import db
from app.auth.email import send_password_reset_email, send_confirmation_email
from app.forms import (LoginForm, RegistrationForm, 
    ResetPasswordRequestForm, ResetPasswordForm)
from app.auth import bp
from app.models import User, Role


@bp.before_app_request
def before_request():
    if current_user.is_authenticated \
        and not current_user.confirmed \
        and request.endpoint[:5] != 'auth.' \
        and request.endpoint != 'static':

        return redirect(url_for('auth.unconfirmed'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('密码或用户名不正确')
            return redirect(url_for('auth.login'))
        login_user(user, form.remember_me.data)
        # NOTE: use next_page here from flask-login documents
        # https://flask-login.readthedocs.io/en/latest/#configuring-your-application
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/login.html', title='登录', form=form)


@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('请查看邮件')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html',
                           title='Reset Password', form=form)


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.commit()
        flash('密码已经重置')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        roles_dict = {
            "臭猪": "StinkyPiggy",
            "傻猪": "SillyPiggy"
        }
        role = Role.query.filter_by(name=roles_dict[username]).first()
        if role.check_validation_hash(str(form.birthday.data)):
            user = User(username=username, role=role,
                email=form.email.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()
        
            send_confirmation_email(user)
            flash('确认邮件已发送至您的邮箱，请点击其中链接完成注册')
            return redirect(url_for('main.index'))
        else:
            flash('生日输入错误')
    return render_template('auth/register.html', title='注册', form=form)


@bp.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash(f'欢迎{current_user.username}')
        return redirect(url_for('main.index'))
    else:
        flash('该链接无效，请重试')
        return redirect(url_for('auth.unconfirmed'))


@bp.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@bp.route('/confirm')
@login_required
def resend_confirmation():
    send_confirmation_email(current_user)
    flash('确认邮件已发送至您的邮箱')
    return redirect(url_for('main.index'))
