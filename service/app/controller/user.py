from datetime import datetime
import random
from flask_restx import Resource, Namespace
from flask import request
from flask_cors import cross_origin
from app.service.user_service import *
from app.service.auth_service import verify_abort
from app.util.user_dto import UserDto
from flask_cors import CORS, cross_origin

api = UserDto.api
_user = UserDto.model
_login = UserDto.model_login
_company = UserDto.model_company
_token = UserDto.model_token
_signup = UserDto.model_signup
_update_receive = UserDto.model_update_receive
_update_send = UserDto.model_update_send

auth_parser = api.parser()
auth_parser.add_argument('Authorization', location='headers')

@api.route('/signup')
class SignUp(Resource):
    @api.doc('Signup')
    @api.expect(_signup, envelope='data')
    @api.response(404, 'Errors with SignUp')
    def post(self):
        data = request.json
        register(email=data["email"], lastName=data["lastName"], firstName=data["firstName"], password=data["password"], company=data["company"])

@api.route('/signin')
class Login(Resource):
    @api.doc('Signin')
    @api.expect(_login, validate=True)
    @api.response(404, 'Wrong credentials or user not found')
    @cross_origin(supports_credentials=True)
    def post(self):
        email = request.json["email"]
        password = request.json["password"]
        token, name = login(email, password)
        return {"message" : "Successfully authenticated", "name" : name}, 201, {"Authorization" :  token, "Access-Control-Expose-Headers": "Authorization"}

@api.route('/verify-token')
class VerifyToken(Resource): 
    @api.expect(auth_parser, validate=True)
    @api.doc('Verifies Token')
    def post(self):
        token = auth_parser.parse_args()['Authorization']
        if verify_abort(token):
            response_object = {
                'status': 'success',
                'message': 'Token is valid'
            }
            return response_object, 201

@api.route('/update')
class UpdateUser(Resource): 
    @api.expect(auth_parser, _update_receive, validate=True, envelope='data')
    @api.doc('Verifies Token')
    def post(self):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        data = request.json
        return update_user(token, firstName = data["firstName"], lastName = data["lastName"])

    @api.expect(auth_parser, validate=True)
    @api.marshal_with(_update_send)
    @api.doc('Receive relevant attributes that can be updated')
    def get(self):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        user = get_user_from_token(token)
        user.company = get_company_from_user(token).name
        return user

@api.route('/company')
class User(Resource):
    @api.expect(auth_parser, validate=True)
    @api.marshal_with(_company)
    @api.doc('Receive company of user')
    def get(self):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        user = get_user_from_token(token)
        user.company = get_company_from_user(token).name
        return user