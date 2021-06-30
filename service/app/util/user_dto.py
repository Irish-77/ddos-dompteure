from flask_restx import Namespace, fields

class UserDto:
    api = Namespace('users', description='user related operations')
    model = api.model('user', {
        'id': fields.Integer(readonly=True, attribute='user_id'),
        'email': fields.String(required=True),
        'lastName': fields.String(required=True),
        'firstName': fields.String(required=True),
        'join_date': fields.DateTime(readonly=True), 
        'company': fields.String(required=True)
    })
    model_update_send = api.model('update', {
        'lastName': fields.String(required=True),
        'firstName': fields.String(required=True),
        'company': fields.String(required=True)
    }) #funktioniert
    model_update_receive = api.model('update', {
        'lastName': fields.String(required=True),
        'firstName': fields.String(required=True)
    }) #funktioniert
    model_login = api.model('login', {
        'email': fields.String(required=True),
        'password': fields.String(required=True)
    }) #funktioniert
    model_token = api.model('token', {
        'token': fields.String(required=True)
    })
    model_company = api.model('company', {
        'company': fields.String(required=True)
    })
    model_signup = api.model('signup', {
        'email': fields.String(required=True),
        'lastName': fields.String(required=True),
        'firstName': fields.String(required=True),
        'password': fields.String(), # not to good idea
        'company': fields.String()
    })