# Herramientas que te pueden servir en el EJPT


## 1. Alert

### Escaneo de enumeración de recursos web (HTTP)

Realiza un escaneo de enumeración de recursos web (HTTP) en el puerto 80 del host alert.htb, usando Nmap, y guarda el resultado en un archivo llamado webScan.

```bash
nmap --script http-enum -p80 alert.htb -oN webScan
```
<br>

| Parte del comando    | Significado                                                                                                                                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nmap`               | Ejecuta Nmap, una herramienta para escaneo de red.                                                                                                                |
| `--script http-enum` | Usa el script NSE llamado `http-enum`, que intenta **descubrir directorios y archivos comunes** en servidores web (tipo `/admin`, `/login`, `/robots.txt`, etc.). |
| `-p80`               | Limita el escaneo al **puerto 80** (HTTP).                                                                                                                        |
| `alert.htb`          | Es el **objetivo**, probablemente una máquina en un entorno tipo HackTheBox.                                                                                      |
| `-oN webScan`        | Guarda la salida en **formato normal** (`-oN`) en un archivo llamado `webScan`.                                                                                   |

<br>
<br>


**📦 ¿Qué es http-enum?**

El script **http-enum** forma parte del motor de scripts de Nmap (NSE: Nmap Scripting Engine) y:

- Intenta detectar rutas sensibles o conocidas en servidores web.
- Se basa en una base de datos de rutas predefinidas.
- Puede ayudarte a encontrar puntos de entrada como:

```
/admin
/config
/phpmyadmin
/wordpress
/login
/test
```

📂 Resultado típico:
El archivo webScan podría contener algo como:

```
PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /admin/             Possible admin folder
|   /robots.txt         Found robots.txt file
|   /wordpress/         WordPress install detected
|_  /login/             Login page
```



**✅ ¿Para qué te sirve esto?**
Ideal para:

- Reconocimiento en pentesting web.
- Enumerar rutas sin usar herramientas externas como gobuster o dirb.
- Saber qué recursos HTTP expone un servidor.


### WhatWeb

El comando utiliza **WhatWeb**, una herramienta de fingerprinting web, para detectar tecnologías utilizadas por un sitio web *(alert.htb en este caso)*.

```
whatweb http://alert.htb
```

**📦 ¿Qué detecta WhatWeb?**

WhatWeb analiza el sitio web y te dice cosas como:

- El servidor web (Apache, Nginx, IIS, etc.)
- El CMS (WordPress, Joomla, Drupal…)
- Bibliotecas JS (como jQuery, Bootstrap)
- Frameworks (Laravel, Express, etc.)
- Headers HTTP interesantes (cookies, X-Powered-By, etc.)
- Posibles tecnologías de seguimiento o seguridad (Google Analytics, reCAPTCHA, WAF, etc.)
- Versiones si están disponibles (como PHP/7.4.3)

**🧠 Ejemplo de salida:**

```bash

http://alert.htb [200 OK] Country[RESERVED][ZZ], IP[10.10.10.100], 
Apache[2.4.29], PHP[7.2.24], Ubuntu, 
X-Powered-By[PHP/7.2.24], 
Title[Login Page]

```


**📌 ¿Para qué sirve?**

- Para hacer reconocimiento web rápido.
- Descubrir vectores de ataque según versiones (ej: PHP desactualizado).
- Identificar la superficie tecnológica de un sitio antes de atacar.

### Payload Inicial XSS (Cross-Site Scripting)

Este es un payload básico de XSS (Cross-Site Scripting) que:

```js
<script>alert(0)</script>
```

- Inyecta una etiqueta `<script>` en una página web.
- Ejecuta el código JavaScript `alert(0)`, lo que muestra una ventana emergente (alert) con el número 0.

**🧠 ¿Por qué se usa alert(0) para probar XSS?**

Porque es una forma segura y visible de comprobar si la inyección de código JavaScript funciona.

**✅ Si aparece la alerta, significa que:**

- El navegador ejecutó tu código.
- La entrada no fue correctamente filtrada ni escapada.
- La página es potencialmente vulnerable a XSS.

**🚨 ¿Qué es XSS exactamente?**

XSS (Cross-Site Scripting) es una vulnerabilidad en aplicaciones web que permite a un atacante inyectar scripts maliciosos que se ejecutan en el navegador de otras personas.

**🔺 Un XSS exitoso puede permitir:**

Robar cookies o tokens de sesión.

- Redirigir a sitios maliciosos.
- Modificar el contenido de la página.
- Registrar pulsaciones del teclado (keylogger).
- Hacer ingeniería social desde el sitio real.



### Comando: python3 -m http.server 80
Este comando levanta un servidor web HTTP básico en el puerto 80 usando Python 3.

**📌 Qué hace:**

- Crea un servidor web que sirve archivos del directorio actual (donde ejecutaste el comando).
- Usa el módulo http.server incorporado en Python.
- Puedes acceder desde un navegador o con curl así:

```
http://<IP_DEL_HOST>:80/
``` 

🧠 **Ejemplo de uso:**

Estás en /home/user/Downloads y corres:


```python
python3 -m http.server 80
``` 

Entonces alguien desde otra máquina puede descargar archivos de esa carpeta desde:

```
http://tu-ip/
```

### Comando: nc -nlvp 6666

Este comando usa Netcat (nc) para escuchar conexiones entrantes en el puerto 6666.

**📌 Significado de las opciones:**

- n: no resuelve DNS.
- l: modo escucha.
- v: verbose (muestra más info).
- p 6666: puerto a escuchar.

**🧠 Ejemplo de uso:**

Sirve para cosas como:

- Esperar una reverse shell.
- Hacer transferencia de archivos.
- Chat simple por TCP.




```
``` 