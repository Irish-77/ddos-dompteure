from flask import Blueprint
from flask_restx import Api
from .user import api as user_ns
from .company import api as company_ns
from .ip import api as ip_ns


blueprint = Blueprint("api", __name__)

api = Api(
    blueprint, title="DDoS", version="1.0", description="DDoS"
)

api.add_namespace(user_ns, path='/user')
api.add_namespace(company_ns, path='/company')
api.add_namespace(ip_ns, path='/ip')