from datetime import datetime
import random
from flask_restx import Resource, Namespace
from flask import request
from flask_cors import cross_origin
from app.service.company_service import *
from app.service.auth_service import verify_abort
from app.util.company_dto import CompanyDto
from flask_cors import CORS, cross_origin

api = CompanyDto.api
_company = CompanyDto.model
_employees = CompanyDto.model_employees
_register = CompanyDto.model_register
auth_parser = api.parser()
auth_parser.add_argument('Authorization', location='headers')

@api.route('/list')
class Companies(Resource):
    @api.doc('Company List')
    # @api.expect(auth_parser, validate=True)
    @api.marshal_list_with(_company, envelope='data')
    @api.doc('Receive list with companies')
    def get(self):
        # token = auth_parser.parse_args()['Authorization']
        # verify_abort(token)
        return get_all_companies()

@api.route('/<string:company>')
class EmployeesFromCompany(Resource):
    @api.doc('Get employess by company')
    @api.marshal_list_with(_employees, envelope='data')
    @api.expect(auth_parser, validate=True)
    @api.response(404, 'Wrong company or company not found')
    def get(self, company):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        return get_all_employees_of_company(company)

@api.route('/register')
class EmployeesFromCompany(Resource):
    @api.doc('register new company')
    @api.expect(_register, envelope='data')
    @api.response(404, 'Errors with Register')
    def post(self):
        data = request.json
        return register(name=data["name"])