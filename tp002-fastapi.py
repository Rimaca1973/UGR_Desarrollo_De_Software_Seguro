from fastapi import FastAPI, HTTPException, Depends, Security, Request, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from fastapi.responses import HTMLResponse
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

load_dotenv()

app = FastAPI()

security = HTTPBasic()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

API_KEY = os.getenv("API_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

if not API_KEY or not JWT_SECRET or not ADMIN_USER or not ADMIN_PASSWORD:
    raise RuntimeError("Faltan variables necesarias en el archivo .env")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

allowed_ips_env = os.getenv("ALLOWED_IPS", "")
ALLOWED_IPS = set(ip.strip() for ip in allowed_ips_env.split(",") if ip.strip())

async def verificar_ip(request: Request):
    client_ip = request.client.host
    if client_ip not in ALLOWED_IPS:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail=f"Acceso denegado para IP {client_ip}")
    return client_ip

async def verificar_api_key(api_key: str = Security(api_key_header), request: Request = None):
    api_key_query = request.query_params.get("api_key")
    if api_key == API_KEY or api_key_query == API_KEY:
        return API_KEY
    raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="API Key inválida")

def verificar_credenciales(cred: HTTPBasicCredentials = Depends(security)):
    if cred.username != ADMIN_USER or cred.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    return cred

def crear_token_jwt(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        to_encode["exp"] = datetime.utcnow() + expires_delta
    else:
        to_encode["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

async def verificar_token_jwt(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Token inválido")
        return username
    except JWTError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Token inválido o expirado")

@app.get("/api/protegida", response_class=HTMLResponse)
async def ruta_protegida(
    client_ip: str = Depends(verificar_ip),
    api_key: str = Depends(verificar_api_key),
    credenciales: HTTPBasicCredentials = Depends(verificar_credenciales)
):
    token = crear_token_jwt(data={"sub": credenciales.username})
    ips_permitidas = "<br>".join(ALLOWED_IPS)
    html = f"""
    <html>
        <head>
            <title>Autenticación exitosa</title>
            <script>
                function copiarToken() {{
                    const token = document.getElementById('jwt').innerText;
                    if (navigator.clipboard) {{
                        navigator.clipboard.writeText(token)
                            .then(() => alert('Token copiado al portapapeles!'))
                            .catch(() => alert('Error al copiar el token.'));
                    }} else {{
                        alert('Tu navegador no soporta el portapapeles.');
                    }}
                }}

                function guardarToken() {{
                    const token = document.getElementById('jwt').innerText;
                    localStorage.setItem('jwt_token', token);
                    document.getElementById('tokenAlmacenado').innerText = token;
                    alert('Token guardado en localStorage!');
                }}

                function usarToken() {{
                    const token = localStorage.getItem('jwt_token');
                    if (!token) {{
                        alert('No hay token guardado.');
                        return;
                    }}

                    fetch('/api/con_token', {{
                        headers: {{ 'Authorization': `Bearer ${{token}}` }}
                    }})
                    .then(res => res.text())
                    .then(html => {{
                        document.open();
                        document.write(html);
                        document.close();
                    }})
                    .catch(err => alert('Error: ' + err.message));
                }}

                function cerrarSesion() {{
                    localStorage.removeItem('jwt_token');
                    document.getElementById('tokenAlmacenado').innerText = '(vacío)';
                    alert('Sesión cerrada. Token eliminado.');
                    window.location.href = '/logout';
                }}

                window.onload = () => {{
                    const token = localStorage.getItem('jwt_token') || '(vacío)';
                    document.getElementById('tokenAlmacenado').innerText = token;
                }}
            </script>
        </head>
        <body>
            <h2>¡ Acceso concedido ! </h2>
            <ul>
                <li><b>Usuario :</b> {credenciales.username}</li>
                <li><b>Contraseña :</b> {credenciales.password}</li>
		<li><b>API Key :</b> {api_key}</li>
                <li><b>JWT Secret :</b> {JWT_SECRET}</li>
		<li><b>Su IP :</b> {client_ip}</li>                
		<li><b>IPs Permitidas :</b><br> {ips_permitidas}</li>
                <li><b>JWT generado :</b> <code id='jwt'>{token}</code></li>
            </ul>
            <button onclick="copiarToken()">Copiar Token</button>
            <button onclick="guardarToken()">Guardar Token</button>
            <button onclick="usarToken()">Usar Token en /api/con_token</button>
            <br><br>
            <h4>📦 Token almacenado en localStorage:</h4>
            <code id="tokenAlmacenado">(vacío)</code>
            <br><br>
            <button onclick="cerrarSesion()">Cerrar sesión</button>
        </body>
    </html>
    """
    return html

@app.get("/api/con_token", response_class=HTMLResponse)
async def acceso_con_token(username: str = Depends(verificar_token_jwt)):
    html = f"""
    <html>
        <head>
            <title>Validación JWT</title>
        </head>
        <body>
            <h2>✅ Hola <b>{username}</b>, accediste con un JWT válido!</h2>
            <p>Esta es una página protegida usando JSON Web Token.</p>
            <button onclick="window.location.href='/logout'">Cerrar sesión</button>
        </body>
    </html>
    """
    return html

@app.get("/logout")
async def logout():
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Sesión cerrada")
