from flask import Flask, request, Response
from functools import wraps
from flask_restx import Api, Resource
from dotenv import load_dotenv
from datetime import datetime
import os

# Carga variables del .env
load_dotenv()
API_KEY_ESPERADA = os.getenv("API_KEY")
IPS_PERMITIDAS = [ip.strip() for ip in os.getenv("ALLOWED_IPS", "").split(",") if ip.strip()]
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

app = Flask(__name__)

# Swagger
authorizations = {
    'basicAuth': {'type': 'basic'},
    'apiKeyAuth': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'}
}
api = Api(app, title="API Protegida y Colorida 🌈", description="Requiere IP autorizada, API Key y autenticación básica con mensajes coloridos.", authorizations=authorizations, security=[{'basicAuth': []}, {'apiKeyAuth': []}], doc="/docs")
ns = api.namespace("protegida", description="Ruta protegida con autenticación triple")

# HTML response helper
def html_response(content, status=200, headers=None):
    return Response(content, status=status, mimetype='text/html', headers=headers or {})

# Decorador de autenticación completa
def autenticacion_doble(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        ip_origen = request.remote_addr

        if ip_origen not in IPS_PERMITIDAS:
            html = f"""
            <html><body style="background:#ffdddd; font-family:Arial; color:#900; text-align:center; padding:2em;">
                <h1>⚠️ Acceso denegado</h1>
                <p>IP <b>{ip_origen}</b> no permitida.</p>
                <p>IPs permitidas: <b>{', '.join(IPS_PERMITIDAS)}</b></p>
            </body></html>"""
            return html_response(html, status=403)

        api_key = request.headers.get('X-API-Key') or request.args.get('apikey')
        if not api_key or api_key != API_KEY_ESPERADA:
            html = """
            <html><body style="background:#fff4e5; font-family:Arial; color:#b35c00; text-align:center; padding:2em;">
                <h1>🚫 API Key inválida</h1>
                <p>Incluya una API Key válida en el header <code>X-API-Key</code> o en la query <code>apikey</code>.</p>
            </body></html>"""
            return html_response(html, status=401)

        auth = request.authorization
        if not auth or not (auth.username == ADMIN_USER and auth.password == ADMIN_PASSWORD):
            html = """
            <html>
            <body style="background:#ffe6e6; font-family:Arial; color:#900; text-align:center; padding:2em;">
                <h1>🔒 Autenticación fallida</h1>
                <p>Usuario o contraseña incorrectos.</p>
                <form method="GET">
                    <button type="submit" style="font-size:1.1em; padding:0.5em 1em;">🔄 Reintentar</button>
                </form>
            </body>
            </html>"""
            return html_response(html, status=401, headers={'WWW-Authenticate': 'Basic realm="Login Required"'})

        return f(*args, **kwargs)
    return decorador

@ns.route("/")
class RutaSegura(Resource):
    @api.doc(
        responses={200: 'OK', 401: 'No autorizado', 403: 'IP no permitida'},
        description="Requiere IP válida, API Key y autenticación básica."
    )
    @autenticacion_doble
    def get(self):
        auth = request.authorization
        ip_origen = request.remote_addr
        api_key = request.headers.get('X-API-Key') or request.args.get('apikey')
        fecha_hora = datetime.now().strftime("%H:%M del %d-%m-%Y")

        html = f"""
        <html>
            <head>
                <title>✅ Acceso Concedido</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background: #e6ffe6;
                        color: #2d662d;
                        padding: 2em;
                        text-align: center;
                    }}
                    .info {{
                        margin: 1em auto;
                        background: #ccffcc;
                        border: 2px solid #2d662d;
                        border-radius: 10px;
                        display: inline-block;
                        padding: 1.5em 2em;
                        text-align: left;
                        max-width: 420px;
                        box-shadow: 2px 2px 6px #aaa;
                    }}
                    h1 {{
                        font-size: 2em;
                        color: #145214;
                    }}
                    p {{
                        font-size: 1.1em;
                        margin: 0.4em 0;
                    }}
                    .nota {{
                        font-size: 0.85em;
                        color: #555;
                        margin-top: 2em;
                    }}
                </style>
            </head>
            <body>
                <h1>🎉 Acceso Concedido</h1>
		<img src="/static/logougr.jpg" alt="Logo UGR" style="max-width:450px; margin: 20px auto; display: block;">
                <div class="info">
                    <p><b>Usuario:</b> {auth.username}</p>
                    <p><b>Contraseña:</b> {auth.password}</p>
                    <p><b>API Key:</b> {api_key}</p>
                    <p><b>IP origen:</b> {ip_origen}</p>
                    <p><b>IPs permitidas:</b> {', '.join(IPS_PERMITIDAS)}</p>
                    <p><b>Usted ingresó a las:</b> {fecha_hora}</p>
                </div>
                <p class="nota">⚠️ Datos proporcionados a efectos de ejemplo en laboratorio</p>
            </body>
        </html>
        """
        return html_response(html)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

