from app import db
from sqlalchemy import desc, Index
from sqlalchemy.ext.associationproxy import association_proxy
from datetime import datetime
from .company import Company

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False, unique=True)
    lastName = db.Column(db.String, nullable=False)
    firstName = db.Column(db.String, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    join_date = db.Column(db.DateTime, nullable=False, default=datetime.today())
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'))

    
#Index('user_username_idx', User.username.desc())