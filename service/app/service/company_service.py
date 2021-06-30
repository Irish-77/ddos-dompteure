from flask import abort
from sqlalchemy import func, text
from .auth_service import get_user_from_token, verify_token, create_token
from app.model.company import Company
from app import bcrypt, db
import dateutil.parser

def register(name):

    if get_company_by_name(name) != None:
        abort(400, 'Company already exist')

    company = Company(name = name)
    db.session.add(company)
    db.session.commit()

    response_object = {
        'status': 'success',
        'message': 'Successfully registered'
    }
    return response_object, 201

def get_all_companies():
    return Company.query.all()

def get_all_employees_of_company(company_name):
    company = get_company_by_name(company_name)
    return company.users.all()

def get_company_by_name(company_name):
    return Company.query.filter_by(name=company_name).first()