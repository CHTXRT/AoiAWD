from flask import Blueprint

bp = Blueprint('main', __name__, template_folder='../template')

from . import index, ssh, files, attack, defense, rules, keys, sockets, auth
from .sockets import register_socketio_events
