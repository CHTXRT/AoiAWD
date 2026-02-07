import logging
import os
from flask import Flask
from . import config
from .services import ssh_manager
from . import routes

def create_app():
    # Calculate template folder path (app/ + template)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(base_dir, 'template')
    
    app = Flask(__name__, template_folder=template_dir)
    app.config.from_object('app.config.Config')
    config.Config.init_app(app)
    
    log_file = os.path.join(app.config['DATA_DIR'], 'logs', 'flask.log')
    # Ensure log directory exists just in case (though init_app does it)
    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))

    logging.basicConfig(filename=log_file, level=logging.INFO)
    app.logger.addHandler(logging.FileHandler(log_file))
    with app.app_context():
        ssh_manager._ensure_initialized()
    app.register_blueprint(routes.bp)

    return app