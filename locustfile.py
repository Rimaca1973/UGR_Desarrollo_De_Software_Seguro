from locust import HttpUser, TaskSet, task, between
from requests.auth import HTTPBasicAuth

class UserBehavior(TaskSet):

    def on_start(self):
        # Opcional: autenticación OAuth puede automatizarse, pero para comenzar probamos sin esa parte
        self.api_key = "supersecreta123"
        self.username = "admin"
        self.password = "secret"
        self.headers = {
            "X-API-Key": self.api_key
        }

    @task
    def acceso_ruta_protegida(self):
        self.client.get("/protegida/", headers=self.headers, auth=HTTPBasicAuth(self.username, self.password))

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)
