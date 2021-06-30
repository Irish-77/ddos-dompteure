from flask_restx import Resource, Namespace
from flask import request
from app.service.ip_service import *
from app.service.auth_service import *
from app.util.ip_dto import IPDto

api = IPDto.api
_ip = IPDto.model
_ip_classification = IPDto().ip_classification

auth_parser = api.parser()
auth_parser.add_argument('Authorization', location='headers')

@api.route('/')
class IP(Resource):
    @api.doc('IP')
    @api.expect(auth_parser, [_ip_classification], envelope='data')
    @api.response(400, 'Invalid IP')
    @api.response(403, 'Not Authorized')
    @api.response(404, 'No token provided in Header')
    @api.response(400, 'Invalid Token')
    @api.response(400, 'Token Expired')
    def post(self):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        data = request.json
        data = pd.json_normalize(data)
        return {'classification': new_ip(data)}, 201

@api.route('/whitelist')
class IP(Resource):
    @api.doc('Whitelist IPs')
    @api.marshal_list_with(_ip, envelope='data')
    @api.expect(auth_parser)
    @api.response(403, 'Not Authorized')
    @api.response(404, 'No token provided in Header')
    @api.response(400, 'Invalid Token')
    @api.response(400, 'Token Expired')
    def get(self):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        return get_whitelist()

@api.route('/blacklist')
class IP(Resource):
    @api.doc('Blacklist IPs')
    @api.marshal_list_with(_ip, envelope='data')
    @api.expect(auth_parser)
    @api.response(403, 'Not Authorized')
    @api.response(404, 'No token provided in Header')
    @api.response(400, 'Invalid Token')
    @api.response(400, 'Token Expired')
    def get(self):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        return get_blacklist()

@api.route('/<string:ip>')
class CountsByIP(Resource):
    @api.doc('Counts of benign and ddos classified requests for IP')
    @api.expect(auth_parser)
    @api.response(400, 'Invalid IP')
    @api.response(404, 'IP Not Found')
    @api.response(403, 'Not Authorized')
    @api.response(404, 'No token provided in Header')
    @api.response(400, 'Invalid Token')
    @api.response(400, 'Token Expired')
    def get(self, ip):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        return get_from_log_by_ip(ip)

@api.route('/<string:ip>/status')
class Status(Resource):
    @api.doc('Status of IP')
    @api.marshal_with(_ip)
    @api.expect(auth_parser)
    @api.response(400, 'Invalid IP')
    @api.response(404, 'IP Not Found')
    @api.response(403, 'Not Authorized')
    @api.response(404, 'No token provided in Header')
    @api.response(400, 'Invalid Token')
    @api.response(400, 'Token Expired')
    def get(self, ip):
        token = auth_parser.parse_args()['Authorization']
        verify_abort(token)
        return {
            'ip': ip,
            'status': ip_status(ip)
        }