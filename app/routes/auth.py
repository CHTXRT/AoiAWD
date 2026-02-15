from flask import render_template, redirect, url_for, request, session, flash, current_app
from . import bp

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form.get('token')
        expected_token = current_app.config.get('TEAM_TOKEN')
        
        if token == expected_token:
            session['authenticated'] = True
            return redirect(url_for('main.index'))
        else:
            flash('Invalid Token', 'error')
            
    return render_template('login.html')

@bp.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('main.login'))

@bp.before_app_request
def check_auth():
    # Helper to check if request is for static file
    if request.path.startswith('/static'):
        return

    # Allow login page
    if request.endpoint == 'main.login':
        return
        
    # Allow localhost
    if request.remote_addr in ['127.0.0.1', '::1', 'localhost']:
        return

    # Check if user is authenticated
    auth_status = session.get('authenticated')
    
    if not auth_status:
        return redirect(url_for('main.login'))
