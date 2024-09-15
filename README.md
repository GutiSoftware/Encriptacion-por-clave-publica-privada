Sistema de Cifrado de Archivos por Clave Pública/Privada

Este proyecto es una aplicación de Python que permite cifrar y descifrar archivos utilizando criptografía de clave pública y privada (RSA), junto con cifrado simétrico (AES). La aplicación ofrece una interfaz gráfica interactiva utilizando Pygame, donde los usuarios pueden generar una clave robusta a través de un patrón dibujado en una colmena de hexágonos.

INDICE

-Características

-Requisitos del Sistema

-Instalación de Librerías

-Instrucciones de Uso

-Detalles Técnicos

-Explicación del Código

-Notas Importantes

-Contribuciones


CARACTERÍSTICAS

Cifrado de archivos utilizando una combinación de criptografía simétrica y asimétrica.
Descifrado de archivos protegido mediante una clave robusta generada por el usuario.
Generación de claves RSA (pública y privada) con protección adicional de la clave privada.
Interfaz gráfica interactiva creada con Pygame.
Generación de clave robusta mediante un patrón dibujado en una interfaz de colmena.
Explicación interactiva sobre el cifrado de clave pública y privada.

REQISITOS DEL SISTEMA

Python 3.6 o superior

Sistema operativo: Windows (el script utiliza módulos específicos de Windows como ctypes.windll y tkinter).

INSTALACIÓN DE LIBRERÍAS

El script requiere varias librerías externas. A continuación, se detallan las librerías y cómo instalarlas:

Pygame: Librería para desarrollo de videojuegos y aplicaciones gráficas.

pip install pygame

PyCryptodome: Implementación de algoritmos criptográficos (AES, RSA).

pip install pycryptodome

Cryptography: Librería avanzada para criptografía.

pip install cryptography

Tkinter: Biblioteca estándar para interfaces gráficas. Suele venir preinstalada con Python en Windows.

Si no la tienes instalada, puedes descargarla desde Python.org.

Otros módulos estándar: sys, os, math, json, base64, hashlib, ctypes

Estos módulos vienen incluidos con la instalación estándar de Python.

INSTALACIÓN DE LIBRERÍAS

Clona el Repositorio
git clone https://github.com/tu_usuario/tu_repositorio.git

Navega al Directorio del Proyecto
cd tu_repositorio

Asegúrate de que el Icono está en el Directorio
Coloca el archivo candado.png en el mismo directorio que Cifrado_archivos.py.
Este icono se utiliza para personalizar la ventana de Pygame.

Ejecuta el Script
python Cifrado_archivos.py

INSTRUCCIONES DE USO
Al iniciar la aplicación, se mostrará una interfaz gráfica con las siguientes opciones:
[1] Cifrar archivo
[2] Descifrar archivo
[3] Generar nuevas claves
[ESC] Salir

Generación de Claves:
Selecciona la opción "Generar nuevas claves" en el menú principal.
Se abrirá una interfaz gráfica con una colmena de hexágonos.
Dibuja un patrón coloreando los hexágonos. Puedes hacerlo:
Haciendo clic en los hexágonos.
Manteniendo pulsado el botón izquierdo del ratón y arrastrando sobre los hexágonos.
Una vez que estés satisfecho con el patrón, haz clic en el botón "HECHO".
Selecciona un directorio donde se guardarán:
Clave pública: clave_publica.pem
Clave privada cifrada: clave_privada.pem.enc
Importante: Recuerda el patrón que dibujaste. Será necesario para descifrar tu clave privada más adelante.

Cifrar un Archivo:
Selecciona la opción "Cifrar archivo" en el menú principal.
Carga la clave pública del destinatario (clave_publica.pem).
Selecciona el archivo que deseas cifrar.
El archivo cifrado se guardará en el mismo directorio con la extensión .cifrado.
Envía el archivo cifrado al destinatario.

Descifrar un Archivo:
Selecciona la opción "Descifrar archivo" en el menú principal.
Carga tu clave privada cifrada (clave_privada.pem.enc).
Dibuja el mismo patrón que utilizaste al generar las claves.
Selecciona el archivo cifrado que recibiste (archivo.cifrado).
El archivo descifrado se guardará en el mismo directorio, eliminando la extensión .cifrado.

DETALLES TÉCNICOS
Cifrado Asimétrico (RSA):
Se utiliza para cifrar la clave AES generada aleatoriamente.
Tamaño de clave: 2048 bits.
Clave Pública: utilizada para cifrar (puede compartirse libremente).
Clave Privada: utilizada para descifrar (debe mantenerse en secreto y está protegida adicionalmente con una clave robusta).
Cifrado Simétrico (AES):
Modo de operación: CBC (Cipher Block Chaining).
Tamaño de clave: 256 bits (32 bytes).
Se utiliza para cifrar y descifrar los archivos.
Clave Robusta:
Generada a partir de un patrón dibujado en la interfaz de colmena.
Se utiliza para cifrar y descifrar la clave privada.
Importante: Debes recordar el patrón exacto, ya que es esencial para acceder a tu clave privada.
Interfaz Gráfica (Pygame):
Se utiliza para mostrar el menú principal, la explicación sobre el cifrado y la interfaz de colmena.
Permite interacción con el ratón y el teclado.

EXPLICACIÓN DEL CÓDIGO
Importación de Módulos
import pygame
import sys
import os
from tkinter import Tk, filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padding_asim
from cryptography.hazmat.primitives import serialization, hashes
import base64
import json
import math
import hashlib
import ctypes
pygame: Para la interfaz gráfica y manejo de eventos.
sys, os: Para interacción con el sistema operativo y manejo de rutas.
tkinter: Para diálogos de selección de archivos y directorios.
Crypto (PyCryptodome): Implementación de algoritmos de cifrado simétrico (AES).
cryptography: Implementación de algoritmos de cifrado asimétrico (RSA).
ctypes: Para manipular ventanas y asegurar que la interfaz gráfica esté en primer plano.
Funciones Principales
generar_guardar_claves()
Genera un par de claves RSA (pública y privada).
Solicita al usuario que dibuje un patrón en la colmena para generar una clave robusta.
Cifra la clave privada con AES utilizando la clave robusta.
Guarda la clave pública y la clave privada cifrada en el directorio seleccionado.
cifrar_archivo(ruta_archivo, clave_publica)
Cifra el archivo seleccionado con AES-256 en modo CBC.
Genera una clave AES aleatoria para el cifrado.
Cifra la clave AES con la clave pública del destinatario.
Guarda el archivo cifrado en formato JSON, incluyendo:
Datos cifrados del archivo.
Clave AES cifrada.
Vector de inicialización (IV).
descifrar_archivo(datos_empaquetados, clave_privada, ruta_guardado)
Descifra el archivo utilizando la clave privada del usuario.
Descifra la clave AES con la clave privada.
Descifra los datos del archivo con la clave AES obtenida.
Guarda el archivo descifrado en el mismo directorio, eliminando la extensión .cifrado.
generar_clave_robusta()
Muestra la interfaz de colmena donde el usuario puede dibujar un patrón.
Genera una cadena binaria basada en el patrón (1 para hexágonos pintados, 0 para no pintados).
Aplica SHA-256 a la cadena para obtener una clave robusta de 256 bits.
mostrar_explicacion()
Muestra una breve explicación sobre el cifrado de clave pública y privada en la interfaz gráfica.
Manejo de Eventos e Interfaz Gráfica
El script utiliza bucles de eventos de Pygame para manejar la interacción del usuario.
Se utilizan funciones como dibujar_hexagono() y esta_dentro_hexagono() para manejar la interfaz de colmena.
Se implementa un menú interactivo que permite al usuario navegar entre las opciones.

NOTAS IMPORTANTES
Seguridad del Patrón:
El patrón de la colmena es esencial para proteger tu clave privada.
Debes recordar el patrón exacto para poder descifrar tu clave privada y los archivos cifrados.
No existe una forma de recuperar la clave privada si olvidas el patrón.
Compartir Claves:
No compartas tu clave privada cifrada (clave_privada.pem.enc) con nadie.
Puedes compartir libremente tu clave pública (clave_publica.pem) con quienes deseen enviarte archivos cifrados.
Compatibilidad:
El script está diseñado para Windows debido al uso de módulos específicos.
Para utilizarlo en otros sistemas operativos, es posible que debas modificar partes del código relacionadas con ctypes y tkinter.
Contribuciones
Las contribuciones al proyecto son bienvenidas. Puedes contribuir de la siguiente manera:
Haz un fork del repositorio.
Crea una rama para tu funcionalidad (git checkout -b feature/nueva-funcionalidad).
Realiza tus cambios y agrega commits descriptivos (git commit -am 'Agrego nueva funcionalidad').
Envía tus cambios a tu repositorio (git push origin feature/nueva-funcionalidad).
Abre un Pull Request en GitHub
Puedes bajarte una version ejecutable desde este link: https://sourceforge.net/projects/cifrado/files/Cifrado_archivos.zip/download
