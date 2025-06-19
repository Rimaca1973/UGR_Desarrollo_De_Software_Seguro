# 🛡️ UGR / Universidad del Gran Rosario  
## Desarrollo de Software Seguro – V.TUCS.2.21.2  
### Trabajo Práctico Final  
**Diseño e Implementación de APIs Seguras con Flask, FastAPI y OpenAPI**

Como parte de la materia **Desarrollo de Software Seguro** de la **Universidad del Gran Rosario**, este proyecto documenta el diseño y la implementación de una API.  
El trabajo se desarrolla en **tres etapas**, cada una incrementando los niveles de seguridad operativa.

---

## 🚀 Tecnologías utilizadas

- **Python** 3.10  
- **Flask** 3.1.1  
- **FastAPI** 0.115.12  
- **Uvicorn** 0.34.2  
- **HTTP Basic Auth**  
- **Git / GitHub**

---

## 📋 Requisitos

- Tener **Python 3.10 o superior** instalado  
- Tener **pip** para instalación de dependencias  

---

## 🛠️ Instalación

```bash
git clone https://github.com/rimaca1973/UGR_Desarrollo_De_Software_Seguro.git
cd UGR_Desarrollo_De_Software_Seguro
pip install -r requirements.txt
```

---

## 📦 Entregas

### ✅ Primera Entrega  

Esta primera entrega tiene como propósito analizar los distintos enfoques de autenticación utilizados en APIs, desde los métodos clásicos como la autenticación básica, hasta técnicas más avanzadas como OAuth 2.0 y JWT (usadas en aplicaciones más modernas).  
También evaluamos los aspectos arquitectónicos y de rendimiento de dos frameworks populares de Python: Flask y FastAPI, con un enfoque especial en sus capacidades para integrar mecanismos de autenticación y documentación de APIs mediante OpenAPI.  
En el componente práctico complementamos esta teoría mediante proyectos funcionales, implementando rutas protegidas y generando documentación interactiva con Swagger UI. El objetivo es establecer un enfoque integral en el diseño de APIs seguras y documentadas, creando una buena base para los siguientes trabajos.

📦 La presentacion correspondiente a esta primer entrega se encuentra disponible en : https://github.com/Rimaca1973/UGR_Desarrollo_De_Software_Seguro/blob/main/TP_APIs_1erEntregaF.pdf

### 🔐 Segunda Entrega  

En esta segunda entrega, se presenta un análisis detallado de la implementación de los mecanismos avanzados de autenticación aplicables al Desarrollo De Software Seguro. Se describen los usos, riesgos y buenas prácticas de la autenticación por IP, el uso de API Keys, y de los protocolos OAuth 2.0 y JWT. A lo largo del informe se identificaron vulnerabilidades frecuentes asociadas a cada método y se propusieron medidas de mitigación concretas, destacando la importancia de aplicar controles como el uso de HTTPS, validación de tokens, y la combinación de factores de autenticación. Se concluye que una arquitectura segura
requiere tanto el diseño cuidadoso de los mecanismos de acceso como una continua evaluación de los vectores de ataque comunes.
Se amplian los requerimientos, las documentaciones correspondientes y se actualizan los trabajos.

📦 La presentacion correspondiente a esta segunda entrega se encuentra disponible en : https://github.com/Rimaca1973/UGR_Desarrollo_De_Software_Seguro/blob/main/TP_APIs_2daEntregaF.pdf

### 🧱 Tercera Entrega  

Esta tercer y ultima entrega integramos OAuth 2.0 utilizando GitHub como proveedor, lo que nos permitió validar usuarios mediante autenticación externa y obtener un token válido para acceder a recursos autorizados. También configuramos una lógica de bloqueo de IP ante múltiples intentos fallidos, como medida adicional de seguridad que nos ayuda a elevar los niveles de proteccion, en este caso contra ataques de fuerza bruta.
En conjunto, el trabajo representó un recorrido completo por las distintas formas de proteger una API moderna, entendiendo tanto la lógica técnica como las ventajas de aplicar buenas prácticas desde el diseño. Esta experiencia nos dejó herramientas sólidas para el futuro y una mejor comprensión del rol que juega la seguridad en el desarrollo de software profesional.

📦 La informacion correspondiente a esta tercer entrega se encuentra disponible en : https://github.com/Rimaca1973/UGR_Desarrollo_De_Software_Seguro/blob/main/Ultima%20Entrega%20Desarrollo%20Seguro.pdf

---

## 👤 Autores

- **Cabrera, Ricardo Martín**  
- **Deparsia, Ignacio**  
- **Quaglia, Tomás**  

Estudiantes de la **Tecnicatura Universitaria en Ciberseguridad**  
**Universidad del Gran Rosario**

---

## ⚠️ Descargo de Responsabilidad

> *Este proyecto es parte de una entrega académica. No debe ser usado en producción sin aplicar las medidas de seguridad adecuadas.*

---

## 📝 Licencia

[![Licencia Creative Commons](https://licensebuttons.net/l/by-nc-nd/4.0/88x31.png)](https://creativecommons.org/licenses/by-nc-nd/4.0/deed.es)  
Este proyecto está licenciado bajo la licencia [Creative Commons Atribución-NoComercial-SinDerivadas 4.0 Internacional (CC BY-NC-ND 4.0)](https://creativecommons.org/licenses/by-nc-nd/4.0/deed.es).

Se puede compartir el contenido original del proyecto **siempre y cuando**:

- Se dé crédito apropiado a los autores.  
- No se utilice con fines comerciales.  
- No se modifique el contenido ni se generen obras derivadas.

Para más detalles, consultá los términos completos en el siguiente enlace:  
🔗 https://creativecommons.org/licenses/by-nc-nd/4.0/deed.es
