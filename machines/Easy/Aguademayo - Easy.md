
>[!NOTE] Habilidades: 
> Brainfuck Decode, SUID Privilege Escalation

## Lanzar el laboratorio

Para desplegar el laboratorio de `docker` que estaremos explotando, ejecutaremos los siguientes comandos

~~~ bash
# Descomprimimos el archivo
unzip aguademayo.tar

# Asignamos permisos de ejecución al script que despliega el laboratorio
chmod +x auto_deploy.sh

# si no tienes el comando service
systemctl start docker

# Lanzamos el laboratorio
./auto_deploy.sh aguademayo.tar
~~~

![etc hosts](https://github.com/user-attachments/assets/6e7efbfd-fd04-4fce-b73f-889302bdbebf)


# Reconocimiento
---
## Ping

Comprobamos que la máquina se encuentre activa en la `172.17.0.2`, por comodidad, agregaré esta dirección al archivo `/etc/hosts` con el nombre `aguademayo.local`



~~~ bash
ping -c1 aguademayo.local
~~~


## Nmap

Haremos un primer escaneo por el protocolo TCP para descubrir si la máquina tiene puertos abiertos, lo haremos con `nmap` empleando el siguiente comando

~~~ bash
nmap --open -p- --min-rate 5000 -n -sS -v -Pn $ip -oG allPorts
~~~

![first_nmap_scan](https://github.com/user-attachments/assets/49b10638-7878-43b7-a34f-0a7e3cb2abc2)

- `--open`: Mostrar solamente los puertos abiertos
- `-p-`: Escanear todo el rango de puertos (65535)
- `-sS`: Modo de escaneo TCP SYN, usa una técnica más sigilosa para determinar que el puerto está abierto al no concluir la conexión
- `-n`: No aplicar resolución DNS, lo que acelera el escaneo
- `-Pn`: Deshabilitar el descubrimiento de host, o sea, asume que el objetivo se encuentra activo, por lo que no hace un `ping` previo a `aguademayo.local`
- `-v`: Modo `verbose`, muestra los resultados del escaneo en tiempo real
- `-oG`: Exportar el escaneo a un formato `Grepable`, lo que es más útil a la hora de extraer información de nuestro archivo, como por ejemplo, los puertos abiertos encontrados

### Services Scan

~~~ bash
nmap -sVC -p 22,80 aguademayo.local -oN targeted
~~~

![ports_scan](https://github.com/user-attachments/assets/ffb91eb8-6e7f-44cd-8927-ab8724c33796)


## Http Service

Vemos el puerto `80` que corresponde a un servicio `http`, veamos que hay en él. Podemos usar la herramienta `whatweb` para listar las tecnologías detectadas en el servidor

~~~ bash
whatweb http://172.17.0.2
~~~

![web](https://github.com/user-attachments/assets/970206d2-801c-41fc-9bc5-d82bae6a4533)

## Fuzzing

Lo siguiente que haremos será intentar descubrir posibles directorios existentes en este servicio web, en este caso podemos usar cualquier herramienta de fuzzing, usaré `wfuzz` y `gobuster`
### Wfuzz

~~~ bash
wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 http://aguademayo.local/FUZZ
~~~

![wfuzz_fuzzing](https://github.com/user-attachments/assets/118a1b0f-c47e-43e7-b0ae-481a9c397ec7)

- `-c`: Formato colorizado
- `--hc=404`: Ocultar el código de estado 404 (No encontrado)
- `-w`: Especificar un diccionario de palabras
- `-t 200`: Dividir el proceso en 200 hilos, agilizando la tarea

### Gobuster

~~~ bash
gobuster dir -u http://aguademayo.local -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
~~~

![gobuster fuzzing](https://github.com/user-attachments/assets/53042682-8d30-463e-87b2-1447df299489)

- `dir`: Modo de descubrimiento de directorios y archivos
- `-u`: Dirección URL
- `-w`: Diccionario a usar
- `-t 200`: Establecer 200 subprocesos 

Podemos ver que en ambos casos se ha descubierto el directorio `images`, vamos a ver que contiene con `firefox`, o si no te gusta abandonar la terminal, con `curl`

~~~ bash
curl -sL -X GET http://172.17.0.2/images
~~~

![curl a images](https://github.com/user-attachments/assets/7a09eafc-ab53-485c-9079-72c92a91e74c)

- `-s`: No mostrar progreso o error de la solicitud
- `-L`: Habilitar el redireccionamiento
- `-X`: Especificar el método HTTP a usar

![dir images](https://github.com/user-attachments/assets/502fede3-bd5b-440d-97ab-02620d42bbe3)

Vemos un archivo  `agua_ssh.jpg`, procedemos a traerla a nuestra máquina y ver de qué se trata

![imagen_ssh](https://github.com/user-attachments/assets/8757624b-9779-4469-af7c-4b72bf5c5fcc)

~~~ bash
wget http://aguademayo.local/images/agua_ssh.jpg
~~~

![wget agua_ssh](https://github.com/user-attachments/assets/90bbcbd2-1463-4918-a107-7b0b448d23b3)

El nombre del archivo `agua_ssh.jpg` me parece un tanto raro, ya que contiene `ssh` en el nombre, esto me hace creer que `agua` es un usuario válido en la máquina.

Si hacemos un análisis del archivo o imprimimos los caracteres de la imagen, no encontramos mayores pistas

## Exiftool Analysis

~~~ bash
exiftool agua_ssh.jpg
~~~

![exiftool_analysis](https://github.com/user-attachments/assets/69759702-ede8-411b-bc90-af525c59fce0)


## Strings

~~~ bash
strings agua_ssh.jpg
~~~

![listar caracteres](https://github.com/user-attachments/assets/8aba8f9d-253a-4533-a0e2-1528cdcaa042)


# Intrusión
---
## Brainfuck Decode

Si vemos el código fuente podemos ver algo inusual al final del todo en un comentario HTML

![web codigo raro](https://github.com/user-attachments/assets/467905dc-b906-47e8-9f9b-a92ebbefd7df)

Como no sabía a qué me enfrentaba, lo primero que hice fue buscar este comentario HTML en Google

![decode ](https://github.com/user-attachments/assets/a8bfb2fb-b654-494a-bb43-81f6d1be466a)

Podemos ver que hay un mensaje escrito en lenguaje Brainfuck, así que lo decodificaremos con ayuda de esta web `https://dcode.fr/brainfuck-language`
**No olvidemos quitar los caracteres del comentario HTML** (`<!--` y `-->`)

![decrypt](https://github.com/user-attachments/assets/0d8e55e6-bd5e-4690-b69a-3f77d109afc4)

Vemos que el mensaje escondido se trata de la palabra `bebeaguaqueessano`, quizá sea la contraseña del usuario `agua`, por lo que probamos conectarnos por `ssh`

~~~ bash
ssh agua@aguademayo.local
~~~

![entramos por ssh](https://github.com/user-attachments/assets/d00de753-2e0c-4d32-b543-4c7da29f1fb8)


# Escalada de privilegios
---
## Tratamiento TTY

Una vez tenemos acceso, haremos un tratamiento de la TTY para limpiar la pantalla con `Ctrl + L`, para esto cambiaremos el valor de la variable `$TERM`

~~~ bash
export TERM=xterm
~~~

## Sudoers

Primeramente veremos si tenemos privilegios `sudo` con el siguiente comando

~~~ bash
sudo -l
~~~

![sudo -l](https://github.com/user-attachments/assets/4c4df56f-36ed-4d14-87f8-5df9ce7673c0)

- `-l`: Enumerar los comandos permitidos (o prohibidos) invocables por el usuario en la máquina actual


Existe `bettercap` en la máquina y podemos ejecutarlo sin proporcionar contraseña, ejecutaremos el binario

~~~ bash
sudo bettercap
~~~

![exec bettercap with sudo](https://github.com/user-attachments/assets/8b2b3182-7951-491f-a10f-8ef29cd2139e)

Veamos el panel de ayuda con el comando `help`

![bettercap help](https://github.com/user-attachments/assets/3752382d-c7d9-4f66-acbb-784d1a8385f3)

![help bettercap](https://github.com/user-attachments/assets/42e3730f-aa2b-414c-8185-d124b5e4cd7b)


## SUID Privilege Escalation

Esta opción (`!`) nos permite ejecutar un comando a nivel de sistema, así que podemos asignar el privilegio SUID a la `bash` para ejecutarla como `root`, para eso, lo haremos con el comando `chmod`, dentro de la consola interactiva de `bettercap` ejecutamos el siguiente comando

~~~ bash
! chmod u+s /bin/bash
~~~

También podemos hacer esto con un solo comando con la opción `-eval` 

~~~ bash
sudo bettercap -eval "! chmod u+s /bin/bash"
~~~

![cambiar el privilegio onliner](https://github.com/user-attachments/assets/48db4ad6-d528-42c2-a14d-f0fd8c97b612)

- `-eval`: Ejecutar un comando en la máquina


## Root time

Ahora supuestamente asignamos la capacidad de ejecutar `bash` como el usuario `root`, lo podemos verificar con el comando `ls -l /bin/bash` para listar los permisos.

![bash permisions](https://github.com/user-attachments/assets/d3d00e95-9394-47b6-8d64-6bb444c6eae4)

Así que ejecutamos `bash` como el propietario, y nos convertimos en el usuario `root`

~~~ bash
bash -p
~~~

- `-p`: Ejecutar como el usuario original

![bash como root](https://github.com/user-attachments/assets/3bdbe0a3-ad67-4758-80ed-03c209b20d9b)
