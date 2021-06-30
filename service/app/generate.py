import datetime
import random
import os
from pathlib import Path
from sqlalchemy import text
import pandas as pd
import numpy as np
from app import db
from app.model import *
from app.service.ip_service import *
from app.service import user_service
from app.service import company_service

def saveAllToDB(data):
    db.session.add_all(data)
    db.session.commit()

def create_companies():
    c1 = company_service.register("Apple")
    c2 = company_service.register("Accenture")
    c3 = company_service.register("SAP")
    print('added: companies')

def createUsers():
    user_service.register(email="herbert@gmail.com", lastName="Herbert", firstName="Herbert", password="Passwort123!", company="Apple")
    user_service.register(email="ronho@gail.com", lastName="Holzapfel", firstName="Ron", password="Passwort123!", company="Accenture")
    user_service.register(email="max@gmail.com", lastName="Mustermann", firstName="Max", password="Passwort123!", company="SAP")
    user_service.register(email="jobs@mail.de", lastName="Jobs", firstName="Steve", password="Passwort123!", company="Apple")
    print('added: users')
    
def create_ips():
    path = Path('./app/dummy_data.csv')
    data = pd.read_csv(path)
    data = data[~data['Flow Byts/s'].isin([np.inf, -np.inf])]
    data = data.dropna(subset=['Flow Byts/s'])
    data = data.iloc[:, :-1]
    new_ip(data)
    print('added: ips')

def generate():
    create_companies()
    createUsers()
    create_ips()