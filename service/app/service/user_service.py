from flask import abort
from sqlalchemy import func, text
from .auth_service import get_user_from_token, verify_token, create_token
from app.model.user import User, Company
from .company_service import get_company_by_name
from app import bcrypt, db
import dateutil.parser


def get_company_from_user(token):
    user = get_user_from_token(token)
    c_id = user.company_id
    return Company.query.get(c_id)

def get_user_by_id(user_id: int):
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        abort(404, 'User Not Found')
    else:
        return user

def get_all_users():
    users = User.query.all()
    return users

def get_user_by_email(email):
    user = User.query.filter_by(email=email).first()
    if user == None:
        abort(400, 'User not found')
    return user

def register(email, lastName, firstName, password, company):

    if User.query.filter_by(email=email).first() != None:
        abort(400, 'User already exist')
    
    hashed_password = bcrypt.generate_password_hash(password, 10)
    c = get_company_by_name(company)
    user = User(email=email, lastName=lastName, firstName=firstName, password=hashed_password, company_id = c.company_id)
    db.session.add(user)
    db.session.commit()

    response_object = {
        'status': 'success',
        'message': 'Successfully created'
    }
    return response_object, 201

def login(email, password):
    user = get_user_by_email(email)
    password_matched_email = user.password
    if not bcrypt.check_password_hash(password_matched_email, password):
        abort(400, 'Wrong credentials')
    token = create_token(email)
    name = user.firstName + " " + user.lastName
    return token, name

def update_user(token, firstName, lastName):
    user = get_user_from_token(token)

    user.firstName = firstName
    user.lastName = lastName

    db.session.commit()
    response_object = {
        'status': 'success',
        'message': 'Successfully updated'
    }
    return response_object, 201