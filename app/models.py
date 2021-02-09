from collections import defaultdict
from datetime import datetime
from time import time

from flask import current_app
from flask_login import UserMixin
from hashlib import md5
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role')
    def __repr__(self):
        return f"<Role {self.name}>"

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def generate_confirmation_token(self, expiration=3600):
        serializer = Serializer(current_app.config['SECRET_KEY'], expiration)
        return serializer.dumps({'confirm': self.id})

    def confirm(self, token):
        serializer = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = serializer.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False

        self.confirmed = True
        db.session.commit()
        return True

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
                {'reset_password': self.id, 'exp': time() + expires_in},
                current_app.config['SECRET_KEY'], algorithm='HS256'
            )
    
    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

# NOTE: Flask-login needs a callback function to load user
# with a unique id
@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))




