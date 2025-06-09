from flask import Flask, request, Response, redirect, url_for, session
from functools import wraps
from flask_restx import Api, Resource
from flask_httpauth import HTTPBasicAuth
from dotenv import load_dotenv
from datetime import datetime
import os
import requests

# Carga variables del .env
load_dotenv()
API_KEY_ESPERADA = os.getenv("API_KEY")
IPS_PERMITIDAS = [ip.strip() for ip in os.getenv("ALLOWED_IPS", "").split(",") if ip.strip()]
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

app = Flask(__name__)
app.secret_key = os.getenv("JWT_SECRET") or "supersecreto"

# Inicializa Flask-HTTPAuth
auth = HTTPBasicAuth()

# Contador de intentos fallidos por IP
intentos_fallidos = {}

# Swagger
authorizations = {
    'basicAuth': {'type': 'basic'},
    'apiKeyAuth': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'}
}
api = Api(app, title="Desarrollo Seguro De Software - API INTEGRADORA", description="Requiere IP autorizada, API Key y autenticación básica con GitHub OAuth.", authorizations=authorizations, security=[{'basicAuth': []}, {'apiKeyAuth': []}], doc="/docs")

ns = api.namespace("protegida", description="Ruta protegida con autenticación triple")

# Verificación de usuario y contraseña con control de intentos
@auth.verify_password
def verify_password(username, password):
    ip = request.remote_addr
    if intentos_fallidos.get(ip, 0) >= 3:
        return None  # Bloqueado

    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        intentos_fallidos[ip] = 0  # Resetea si se autentica correctamente
        return username
    else:
        intentos_fallidos[ip] = intentos_fallidos.get(ip, 0) + 1
        return None

# Personalización del error 401
@auth.error_handler
def unauthorized():
    ip = request.remote_addr
    if intentos_fallidos.get(ip, 0) >= 3:
        return html_response(f"""
        <html><body style='text-align:center; font-family:sans-serif;'>
            <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px;'><br><br>
            <h1>❌ Acceso bloqueado temporalmente</h1>
            <p>Demasiados intentos fallidos desde IP: {ip}</p>
        </body></html>
        """, status=403)

    return Response("""
    <html>
    <head>
        <style>
            body { font-family: sans-serif; background: #ffe6e6; text-align: center; padding: 3em; }
            .error-box { background: #ffcccc; padding: 2em; border-radius: 10px; width: 400px; margin: auto; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1 { color: #990000; }
            p { color: #660000; }
        </style>
    </head>
    <body>
        <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px;'><br><br>
        <div class="error-box">
            <h1>🔒 Autenticación fallida</h1>
            <p>Usuario o contraseña incorrectos.</p>
            <p>Verifica tus credenciales e intenta nuevamente.</p>
        </div>
    </body>
    </html>
    """, status=401, mimetype='text/html')

# HTML helper
def html_response(content, status=200, headers=None):
    return Response(content, status=status, mimetype='text/html', headers=headers or {})

# Decorador de autenticación doble
def autenticacion_doble(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        ip_origen = request.remote_addr

        if intentos_fallidos.get(ip_origen, 0) >= 3:
            return html_response(f"""
            <html><body style='text-align:center; font-family:sans-serif;'>
                <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px; margin-top:2em;'><br>
                <h1>❌ Acceso bloqueado temporalmente para esta IP: {ip_origen}</h1>
                <p>Demasiados intentos fallidos.</p>
            </body></html>
            """, status=403)

        if ip_origen not in IPS_PERMITIDAS:
            return html_response(f"""
            <html><body style='text-align:center; font-family:sans-serif;'>
                <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px; margin-top:2em;'><br>
                <h1>🚫 IP no permitida: {ip_origen}</h1>
            </body></html>
            """, status=403)

        api_key = request.headers.get('X-API-Key') or request.args.get('apikey')
        session['api_key'] = api_key
        if not api_key or api_key != API_KEY_ESPERADA:
            return html_response("""
            <html><body style='text-align:center; font-family:sans-serif;'>
                <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px; margin-top:2em;'><br>
                <h1>🔑 API Key inválida</h1>
            </body></html>
            """, status=401)

        if not auth.current_user():
            return unauthorized()

        session['auth_user'] = auth.current_user()
        session['auth_pass'] = request.authorization.password
        if not session.get("oauth_validado"):
            session["despues_oauth"] = request.url
            return redirect("/login/github")

        return f(*args, **kwargs)
    return decorador

@app.route("/login/github")
def login_github():
    ip_origen = request.remote_addr
    api_key = session.get('api_key', 'No disponible')
    auth_user = session.get('auth_user', 'No disponible')
    auth_pass = session.get('auth_pass', 'No disponible')
    fecha_hora = datetime.now().strftime("%H:%M del %d-%m-%Y")

    github_url = f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={url_for('github_callback', _external=True)}"

    return html_response(f"""
    <html><body style='font-family:sans-serif; text-align:center; padding:3em;'>
        <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px;'><br><br>
        <h1>🔍 Verificación completada</h1>
        <div style='background:#cce6ff; padding:2em; width:500px; margin:auto; border-radius:10px; color:#003366;'>
            <p><b>🌐 IP validada:</b> {ip_origen}</p>
            <p><b>🧬 API Key:</b> {api_key}</p>
            <p><b>👤 Usuario:</b> {auth_user}</p>
            <p><b>🔒 Contraseña:</b> {auth_pass}</p>
            <p><b>🕒 Fecha y hora:</b> {fecha_hora}</p>
        </div>
        <a href="{github_url}" style="font-size:1.2em; padding:0.5em 1em; background:#003366; color:white; text-decoration:none; border-radius:8px; display:inline-block; margin-top:2em;">🔑 Autenticación OAuth GitHub</a>
    </body></html>
    """)

@app.route("/callback", endpoint="github_callback")
def callback_func():
    code = request.args.get("code")

    token_response = requests.post("https://github.com/login/oauth/access_token", data={
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': code
    }, headers={'Accept': 'application/json'})

    token_json = token_response.json()
    access_token = token_json.get("access_token")

    user_response = requests.get("https://api.github.com/user", headers={
        'Authorization': f"Bearer {access_token}"
    })
    username = user_response.json().get("login")

    session["oauth_validado"] = True
    session["github_user"] = username
    session["github_token"] = access_token
    destino = session.pop("despues_oauth", "/protegida")
    return html_response(f"""
    <html><body style='text-align:center; font-family:sans-serif; padding:3em;'>
        <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px;'><br><br>
        <h1>✅ Autenticación OAuth Exitosa</h1>
        <p>Bienvenido, {username}!</p>
        <code>{access_token}</code><br><br>
        <a href="{destino}" style="font-size:1.2em; padding:0.5em 1em; background:#2d662d; color:white; text-decoration:none; border-radius:8px;">🔒 Ingresar a Ruta Protegida</a>
    </body></html>
    """)

@ns.route("/")
class RutaSegura(Resource):
    @api.doc(description="Ruta protegida por IP, API Key, autenticación básica y OAuth GitHub")
    @auth.login_required
    @autenticacion_doble
    def get(self):
        auth_user = session.get('auth_user', 'No identificado')
        auth_pass = session.get('auth_pass', 'No disponible')
        ip_origen = request.remote_addr
        api_key = request.headers.get('X-API-Key') or request.args.get('apikey')
        fecha_hora = datetime.now().strftime("%H:%M del %d-%m-%Y")
        github_user = session.get("github_user", "No identificado")
        github_token = session.get("github_token", "No disponible")

        return html_response(f"""
        <html><body style='background:#e6ffe6; padding:2em; text-align:center; font-family:sans-serif;'>
            <img src='/static/logougr.jpg' alt='Logo UGR' style='height:70px;'><br>
            <h1>🛡️ Acceso Concedido</h1>
            <div style='margin:auto; background:#ccffcc; padding:2em; width:40%; border-radius:10px;'>
                <p><b>👤 Usuario:</b> {auth_user}</p>
                <p><b>🔒 Contraseña:</b> {auth_pass}</p>
                <p><b>🧬 API Key:</b> {api_key}</p>
                <p><b>🌐 IP origen:</b> {ip_origen}</p>
                <p><b>✅ IPs permitidas:</b> {', '.join(IPS_PERMITIDAS)}</p>
                <p><b>🕒 Ingreso a las:</b> {fecha_hora}</p>
                <hr>
                <p><b>GitHub:</b> {github_user}</p>
                <code>{github_token}</code>
            </div>
            <p style='font-size:0.85em; color:#555;'>⚠️ Datos de ejemplo con fines académicos</p>
        </body></html>
        """)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
