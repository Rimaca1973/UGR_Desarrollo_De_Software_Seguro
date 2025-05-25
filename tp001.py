from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI()
security = HTTPBasic()

def verificar_credenciales(credenciales: HTTPBasicCredentials = Depends(security)):
    usuario_correcto = credenciales.username == "admin"
    contrasena_correcta = credenciales.password == "secret"
    if not (usuario_correcto and contrasena_correcta):
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    return credenciales.username

@app.get("/api/protegida")
def ruta_protegida(usuario: str = Depends(verificar_credenciales)):
    return {"mensaje": f"Acceso concedido a {usuario}!"}
