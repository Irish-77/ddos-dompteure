from flask_restx import Namespace, fields

class CompanyDto:
    api = Namespace('companies', description='company related operations')
    model = api.model('company', {
        'id': fields.Integer(readonly=True, attribute='company_id'),
        'name': fields.String(required=True)
    })
    model_register = api.model('register', {
        'name': fields.String(required=True)
    })
    model_employees = api.model('employees', {
        'id': fields.Integer(readonly=True, attribute='user_id'),
        'lastName': fields.String(required=True),
        'firstName': fields.String(required=True),
        'email': fields.String(required=True)
    })