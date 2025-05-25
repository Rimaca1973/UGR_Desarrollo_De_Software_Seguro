from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

def verificar_autenticacion(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == 'admin' and auth.password == 'secret'):
            return jsonify({"mensaje": "Autenticacion fallida!"}), 401
        return f(*args, **kwargs)
    return decorador

@app.route('/api/protegida', methods=['GET'])
@verificar_autenticacion
def api_protegida():
    return jsonify({"mensaje": "Acceso concedido!"})

if __name__ == '__main__':
    app.run()
