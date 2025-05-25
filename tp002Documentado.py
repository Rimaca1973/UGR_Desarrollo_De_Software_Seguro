from flask import Flask, request, jsonify, make_response
from functools import wraps
from flask_restx import Api, Resource

app = Flask(__name__)

# 🔐 Configuración de Swagger con autenticación básica
authorizations = {
    'basicAuth': {
        'type': 'basic'
    }
}

api = Api(
    app,
    title="API Segura",
    description="Documentación con Swagger",
    authorizations=authorizations,
    security='basicAuth',
    doc="/docs"  # Documentación Swagger disponible en /docs
)

# 🔧 Namespace: agrupa los endpoints bajo /protegida/
ns = api.namespace("protegida", description="Operaciones protegidas")

# 🛡️ Decorador de autenticación básica
def verificar_autenticacion(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == 'admin' and auth.password == 'secret'):
            response = make_response(jsonify({"mensaje": "Autenticación fallida!"}), 401)
            response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
            return response
        return f(*args, **kwargs)
    return decorador

# 🔐 Endpoint protegido documentado
@ns.route("/")
class RutaProtegida(Resource):
    @api.doc(security='basicAuth', responses={200: 'OK', 401: 'No autorizado'})
    @verificar_autenticacion
    def get(self):
        return {"mensaje": "Acceso concedido!"}

# 🚀 Inicio de la app
if __name__ == '__main__':
    app.run(debug=True)