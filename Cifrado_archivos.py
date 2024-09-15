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

# Inicializar pygame
pygame.init()

# Ruta del ejecutable
executable_path = sys.argv[0]

# Carpeta del ejecutable
executable_dir = os.path.dirname(executable_path)


# Construir la ruta completa al icono
ruta_icono = os.path.join(executable_dir, 'candado.png')  # Reemplaza 'icono.png' por el nombre de tu archivo de icono

# Cargar y establecer el icono
try:
    icono = pygame.image.load(ruta_icono)
    pygame.display.set_icon(icono)
except pygame.error as e:
    print(f"No se pudo cargar el icono: {e}")


# Configuración de la ventana
ANCHO, ALTO = 800, 600  # Aumentamos el alto para acomodar la interfaz de Colmena
ventana = pygame.display.set_mode((ANCHO, ALTO))
pygame.display.set_caption('Sistema de Cifrado de Archivos por clave pública/privada')

# Colores
BLANCO = (255, 255, 255)
NEGRO = (0, 0, 0)
VERDE = (0, 255, 0)
AZUL_OSCURO = (0, 0, 139)
ROJO = (255, 0, 0)
AMARILLO = (255, 223, 0)
AZUL = (0, 0, 255)
PLATEADO = (192, 192, 192)  # Color plateado para el texto

# Fuente para el texto
fuente = pygame.font.Font(None, 32)

# Fuente para el texto "GutiSoft 2024"
fuente_gutisoft = pygame.font.SysFont('Courier', 20)
texto_gutisoft = fuente_gutisoft.render('GutiSoft 2024', True, PLATEADO)
# Obtener el rectángulo del texto para posicionarlo
rect_texto = texto_gutisoft.get_rect()
rect_texto.bottomright = (ANCHO - 10, ALTO - 10)  # Margen de 10 píxeles desde el borde

# Función para seleccionar un archivo con un título personalizado
def seleccionar_archivo(titulo="Seleccionar archivo"):
    root = Tk()
    root.withdraw()  # Ocultar la ventana principal de tkinter
    root.attributes('-topmost', True)  # Asegurar que la ventana esté en primer plano
    archivo = filedialog.askopenfilename(title=titulo)  # Título personalizado
    return archivo

# Función para seleccionar un directorio en Windows
def seleccionar_directorio(titulo="Seleccionar una carpeta para guardar las claves"):
    root = Tk()
    root.withdraw()  # Ocultar la ventana principal de tkinter
    root.attributes('-topmost', True)  # Asegurar que la ventana esté en primer plano
    directorio = filedialog.askdirectory(title=titulo)  # Abrir el diálogo de selección de directorio
    return directorio

# Función para generar y guardar las claves RSA en archivos (cifrada)
def generar_guardar_claves():
    # Generar clave privada y pública en memoria
    clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    clave_publica = clave_privada.public_key()

    # Seleccionar directorio para guardar las claves
    directorio = seleccionar_directorio()

    if directorio:
        # Guardar la clave pública en disco
        with open(os.path.join(directorio, "clave_publica.pem"), "wb") as f:
            f.write(clave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Generar la clave robusta usando la interfaz de Colmena
        clave_robusta = generar_clave_robusta()

        if clave_robusta:
            # Cifrar la clave privada en memoria utilizando la clave robusta
            clave_privada_cifrada = cifrar_clave_privada_en_memoria(clave_robusta, clave_privada)

            # Guardar la clave privada cifrada en disco
            ruta_clave_privada_cifrada = os.path.join(directorio, "clave_privada.pem.enc")
            with open(ruta_clave_privada_cifrada, "wb") as f:
                f.write(clave_privada_cifrada)

            return f"Claves guardadas y clave privada cifrada en {directorio}"
        else:
            return "Error al generar la clave robusta."

    else:
        return "No se seleccionó un directorio."

# Función para cifrar la clave privada en memoria
def cifrar_clave_privada_en_memoria(clave_robusta, clave_privada):
    # Serializar la clave privada en memoria
    clave_privada_serializada = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Crear un cifrador AES con la clave robusta
    cipher_aes = AES.new(clave_robusta[:32].encode(), AES.MODE_CBC)  # AES-256 requiere 32 bytes
    iv = cipher_aes.iv

    # Cifrar la clave privada
    clave_privada_cifrada = cipher_aes.encrypt(pad(clave_privada_serializada, AES.block_size))

    # Devolver la clave privada cifrada (IV + datos cifrados)
    return iv + clave_privada_cifrada

# Función para cargar y descifrar la clave privada cifrada
def cargar_clave_privada_cifrada():
    while True:  # Bucle para repetir el diálogo si hay un error
        # Usar el diálogo de selección de archivo para que el usuario elija la clave privada cifrada
        root = Tk()
        root.withdraw()  # Ocultar la ventana principal de tkinter
        root.attributes('-topmost', True)  # Asegurar que la ventana esté en primer plano
        ruta_clave_privada_cifrada = filedialog.askopenfilename(title="Seleccionar clave privada cifrada (.pem.enc)")

        if ruta_clave_privada_cifrada:
            try:
                # Generamos la clave robusta utilizando la interfaz de Colmena
                clave_robusta = generar_clave_robusta()

                if not clave_robusta:
                    raise ValueError("No se pudo generar la clave robusta.")

                # Cargar y descifrar la clave privada
                with open(ruta_clave_privada_cifrada, "rb") as f:
                    datos_cifrados = f.read()

                iv = datos_cifrados[:16]  # El IV está en los primeros 16 bytes
                datos_encriptados = datos_cifrados[16:]  # El resto son los datos cifrados

                # Crear un descifrador AES con la clave robusta
                cipher_aes = AES.new(clave_robusta[:32].encode(), AES.MODE_CBC, iv)
                clave_privada_descifrada = unpad(cipher_aes.decrypt(datos_encriptados), AES.block_size)

                # Cargar la clave privada descifrada desde los datos descifrados
                return serialization.load_pem_private_key(clave_privada_descifrada, password=None)

            except (ValueError, KeyError) as e:
                # Mostrar mensaje de error si no se pudo cargar/descifrar la clave privada
                ventana.fill(BLANCO)
                mostrar_texto(f"ERROR: {str(e)}", 20, 150, color=ROJO, tamano_fuente=26)
                mostrar_texto("Selecciona nuevamente la clave.", 20, 200, color=AZUL_OSCURO, tamano_fuente=26)
                # Dibujar el texto "GutiSoft 2024"
                ventana.blit(texto_gutisoft, rect_texto)
                pygame.display.update()
                pygame.time.wait(3000)
                continue  # Volver a mostrar el diálogo
        else:
            ventana.fill(BLANCO)
            mostrar_texto("No se seleccionó un archivo de clave privada.", 20, 150, color=ROJO, tamano_fuente=26)
            # Dibujar el texto "GutiSoft 2024"
            ventana.blit(texto_gutisoft, rect_texto)
            pygame.display.update()
            pygame.time.wait(3000)
            return None

def cargar_clave_publica():
    while True:  # Bucle para repetir el diálogo si hay un error
        # Usar el diálogo de selección de archivo para que el usuario elija la clave pública
        root = Tk()
        root.withdraw()  # Ocultar la ventana principal de tkinter
        root.attributes('-topmost', True)  # Asegurar que la ventana esté en primer plano
        ruta_clave_publica = filedialog.askopenfilename(title="Seleccionar clave pública")

        if ruta_clave_publica:
            try:
                # Intentar cargar la clave pública desde la ruta seleccionada
                with open(ruta_clave_publica, "rb") as f:
                    return serialization.load_pem_public_key(f.read())
            except ValueError:
                # Mostrar mensaje de error si la clave pública es incorrecta
                ventana.fill(BLANCO)
                mostrar_texto("ERROR: Archivo de clave pública incorrecto.", 20, 150, color=ROJO, tamano_fuente=26)
                mostrar_texto("Selecciona nuevamente la clave.", 20, 200, color=AZUL_OSCURO, tamano_fuente=26)
                # Dibujar el texto "GutiSoft 2024"
                ventana.blit(texto_gutisoft, rect_texto)
                pygame.display.update()
                pygame.time.wait(3000)
                continue  # Volver a mostrar el diálogo
        else:
            ventana.fill(BLANCO)
            mostrar_texto("No se seleccionó un archivo de clave pública.", 20, 150, color=ROJO, tamano_fuente=26)
            # Dibujar el texto "GutiSoft 2024"
            ventana.blit(texto_gutisoft, rect_texto)
            pygame.display.update()
            pygame.time.wait(3000)
            return None

def cifrar_archivo(ruta_archivo, clave_publica):
    if ruta_archivo:
        # Leer el archivo en binario
        with open(ruta_archivo, "rb") as f:
            datos = f.read()

        clave_aes = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher_aes = AES.new(clave_aes, AES.MODE_CBC, iv)
        datos_cifrados = cipher_aes.encrypt(pad(datos, AES.block_size))

        clave_aes_cifrada = clave_publica.encrypt(
            clave_aes,
            padding_asim.OAEP(mgf=padding_asim.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        datos_a_enviar = {
            "datos_cifrados": base64.b64encode(datos_cifrados).decode('utf-8'),
            "clave_aes_cifrada": base64.b64encode(clave_aes_cifrada).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8')
        }

        # Obtener el directorio y el nombre base del archivo original
        directorio, nombre_archivo = os.path.split(ruta_archivo)
        # Crear un nuevo nombre para el archivo cifrado, añadiendo ".cifrado"
        nombre_cifrado = f"{nombre_archivo}.cifrado"
        ruta_archivo_cifrado = os.path.join(directorio, nombre_cifrado)

        # Guardar el bloque cifrado en un nuevo archivo en el mismo directorio
        with open(ruta_archivo_cifrado, "w") as f:
            f.write(base64.b64encode(json.dumps(datos_a_enviar).encode('utf-8')).decode('utf-8'))

        return f"Archivo cifrado guardado como: {nombre_cifrado}"
    else:
        return "No se seleccionó un archivo para cifrar."

# Función para descifrar un archivo
def descifrar_archivo(datos_empaquetados, clave_privada, ruta_guardado):
    try:
        # Decodificar los datos cifrados
        datos_decodificados = json.loads(base64.b64decode(datos_empaquetados).decode('utf-8'))
        datos_cifrados = base64.b64decode(datos_decodificados['datos_cifrados'])
        clave_aes_cifrada = base64.b64decode(datos_decodificados['clave_aes_cifrada'])
        iv = base64.b64decode(datos_decodificados['iv'])

        # Descifrar la clave AES con la clave privada
        clave_aes_descifrada = clave_privada.decrypt(
            clave_aes_cifrada,
            padding_asim.OAEP(mgf=padding_asim.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Usar la clave AES descifrada para descifrar el archivo
        cipher_aes_descifrar = AES.new(clave_aes_descifrada, AES.MODE_CBC, iv)
        datos_descifrados = unpad(cipher_aes_descifrar.decrypt(datos_cifrados), AES.block_size)

        # Restaurar el nombre original quitando la extensión ".cifrado"
        directorio, nombre_archivo_cifrado = os.path.split(ruta_guardado)
        nombre_descifrado = nombre_archivo_cifrado.replace(".cifrado", "")
        ruta_archivo_descifrado = os.path.join(directorio, nombre_descifrado)

        # Guardar los datos descifrados en un archivo
        with open(ruta_archivo_descifrado, "wb") as f:
            f.write(datos_descifrados)

        return f"Archivo descifrado y guardado como: {nombre_descifrado}"
    except Exception as e:
        return f"Error al descifrar el archivo: {str(e)}"

# Función para mostrar texto en la pantalla con tamaño y color personalizados
def mostrar_texto(texto, x, y, color=NEGRO, tamano_fuente=32):
    fuente_personalizada = pygame.font.Font(None, tamano_fuente)  # Tamaño de fuente personalizado
    texto_superficie = fuente_personalizada.render(texto, True, color)
    ventana.blit(texto_superficie, (x, y))

# Explicación breve del cifrado de clave pública/privada
def mostrar_explicacion():
    ventana.fill(BLANCO)
    mostrar_texto("El cifrado de clave pública/privada utiliza dos claves:", 20, 10, color=AZUL_OSCURO, tamano_fuente=24)
    mostrar_texto("1. Una clave pública para cifrar datos, que puede compartirse libremente.", 20, 40, color=AZUL, tamano_fuente=24)
    mostrar_texto("2. Una clave privada para descifrar datos, que debe mantenerse en secreto.", 20, 70, color=AZUL, tamano_fuente=24)
    mostrar_texto("Este sistema asegura que solo el destinatario pueda descifrar los datos.", 20, 100, color=AZUL, tamano_fuente=24)
    # Dibujar el texto "GutiSoft 2024"
    ventana.blit(texto_gutisoft, rect_texto)

# Menú principal interactivo en pygame
def menu():
    pygame.display.set_caption('Sistema de Cifrado de Archivos por clave pública/privada')
    # Traer la ventana de Pygame al frente y hacerla la ventana activa
    hwnd = pygame.display.get_wm_info()['window']
    ctypes.windll.user32.SetForegroundWindow(hwnd)

    fuente_opciones = pygame.font.Font(None, 32)

    opciones = [
        {'texto': '[1]. Cifrar archivo', 'pos': (50, 200), 'accion': '1'},
        {'texto': '[2]. Descifrar archivo', 'pos': (50, 250), 'accion': '2'},
        {'texto': '[3]. Generar nuevas claves', 'pos': (50, 300), 'accion': '3'},
        {'texto': '[ESC]. Salir', 'pos': (50, 350), 'accion': 'salir'},
    ]

    # Inicializamos las superficies de texto y los rectángulos
    for opcion in opciones:
        opcion['fuente'] = fuente_opciones
        opcion['color'] = NEGRO
        texto_surface = opcion['fuente'].render(opcion['texto'], True, opcion['color'])
        rect = texto_surface.get_rect(topleft=opcion['pos'])
        opcion['surface'] = texto_surface
        opcion['rect'] = rect

    running = True
    while running:
        ventana.fill(BLANCO)
        mostrar_explicacion()
        mostrar_texto("Selecciona una opción:", 50, 150)
        pos_raton = pygame.mouse.get_pos()

        # Actualizar el color de las opciones y renderizar el texto
        for opcion in opciones:
            if opcion['rect'].collidepoint(pos_raton):
                opcion['color'] = AZUL  # Color al pasar el ratón por encima
            else:
                opcion['color'] = NEGRO
            opcion['surface'] = opcion['fuente'].render(opcion['texto'], True, opcion['color'])
            ventana.blit(opcion['surface'], opcion['rect'])

        for evento in pygame.event.get():
            if evento.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            elif evento.type == pygame.KEYDOWN:
                if evento.key == pygame.K_1:
                    return '1'
                elif evento.key == pygame.K_2:
                    return '2'
                elif evento.key == pygame.K_3:
                    return '3'
                elif evento.key == pygame.K_ESCAPE:
                    pygame.quit()
                    sys.exit()
            elif evento.type == pygame.MOUSEBUTTONDOWN:
                if evento.button == 1:
                    for opcion in opciones:
                        if opcion['rect'].collidepoint(evento.pos):
                            if opcion['accion'] == 'salir':
                                pygame.quit()
                                sys.exit()
                            else:
                                return opcion['accion']

        # Dibujar el texto "GutiSoft 2024" en la esquina inferior derecha
        ventana.blit(texto_gutisoft, rect_texto)
        pygame.display.update()


# Configuración de hexágonos para Colmena
RADIO = 40  # Radio del hexágono
ALTURA = math.sqrt(3) * RADIO / 2  # Altura entre lados del hexágono

# Función para dibujar un hexágono en las coordenadas especificadas
def dibujar_hexagono(ventana, x, y, color):

    puntos = []
    for i in range(6):
        angulo = math.radians(60 * i)
        punto_x = x + RADIO * math.cos(angulo)
        punto_y = y + RADIO * math.sin(angulo)
        puntos.append((punto_x, punto_y))
    pygame.draw.polygon(ventana, color, puntos)
    pygame.draw.polygon(ventana, NEGRO, puntos, 2)  # Dibujar borde del hexágono

# Función para verificar si un punto está dentro de un polígono
def punto_en_poligono(x, y, poligono):
    n = len(poligono)
    dentro = False

    p1x, p1y = poligono[0]
    for i in range(n + 1):
        p2x, p2y = poligono[i % n]
        if y > min(p1y, p2y):
            if y <= max(p1y, p2y):
                if x <= max(p1x, p2x):
                    if p1y != p2y:
                        xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    else:
                        xinters = p1x
                    if p1x == p2x or x <= xinters:
                        dentro = not dentro
        p1x, p1y = p2x, p2y

    return dentro

# Función para detectar si el ratón está dentro de un hexágono
def esta_dentro_hexagono(x_hex, y_hex, pos_raton):
    puntos = []
    for i in range(6):
        angulo = math.radians(60 * i)
        punto_x = x_hex + RADIO * math.cos(angulo)
        punto_y = y_hex + RADIO * math.sin(angulo)
        puntos.append((punto_x, punto_y))

    return punto_en_poligono(pos_raton[0], pos_raton[1], puntos)

# Generar las posiciones de los hexágonos en una disposición de colmena
def generar_posiciones_hex():
    posiciones = []
    columnas = [3, 4, 5, 5, 4, 3]  # El patrón de las columnas: 3, 4, 5, 5, 4, 3

    # Ajustar la posición base para centrar los hexágonos en la pantalla
    base_x = 100 + RADIO * 1.3  # Desplazamos un hexágono hacia la derecha
    base_y = 100

    for idx_columna, num_hex in enumerate(columnas):
        for i in range(num_hex):
            # Para columnas impares, desplazamos la columna hacia abajo
            offset_y = ALTURA if idx_columna % 2 == 1 else 0

            # Desplazar la columna 1 (índice 0) hacia abajo un hexágono completo
            if idx_columna == 0:
                offset_y += ALTURA * 2  # Desplazamos la columna 1 hacia abajo un hexágono

            # Para la columna 4 (índice 3), desplazamos todo un hexágono hacia arriba
            if idx_columna == 3:
                offset_y -= ALTURA * 2  # Mover toda la columna hacia arriba un hexágono completo

            x_hex = base_x + idx_columna * (RADIO * 1.5)
            y_hex = base_y + i * (ALTURA * 2) + offset_y
            posiciones.append((x_hex, y_hex))

    return posiciones

# Función para generar una clave robusta a partir del patrón dibujado
def generar_clave_desde_pattern(colores_hexagonos, posiciones_hexagonos):
    # Crear una cadena que represente el patrón basado en los colores de los hexágonos
    patron = ""
    for (x_hex, y_hex) in posiciones_hexagonos:
        if colores_hexagonos[(x_hex, y_hex)] == AZUL:
            patron += "1"  # Azul representará '1'
        else:
            patron += "0"  # Amarillo representará '0'

    # Usamos un hash SHA-256 para convertir el patrón en una clave robusta
    hash_pattern = hashlib.sha256(patron.encode()).hexdigest()

    # Devolver la clave generada a partir del patrón
    return hash_pattern

# Función para dibujar el botón "Hecho"
def dibujar_boton(ventana, x, y, ancho, alto, texto):
    # Dibujar el rectángulo del botón
    pygame.draw.rect(ventana, (200, 200, 200), (x, y, ancho, alto))
    pygame.draw.rect(ventana, NEGRO, (x, y, ancho, alto), 2)

    # Dibujar el texto del botón
    fuente_boton = pygame.font.Font(None, 40)
    texto_superficie = fuente_boton.render(texto, True, NEGRO)
    ventana.blit(texto_superficie, (x + 10, y + 10))

# Función para verificar si el botón fue clicado
def boton_clicado(pos_raton, x, y, ancho, alto):
    if x < pos_raton[0] < x + ancho and y < pos_raton[1] < y + alto:
        return True
    return False

def generar_clave_robusta():
    pygame.display.set_caption('Sistema de Cifrado/Descifrado de clave pública con dibujo')
    
    # Traer la ventana de Pygame al frente y hacerla la ventana activa
    hwnd = pygame.display.get_wm_info()['window']
    ctypes.windll.user32.SetForegroundWindow(hwnd)
    
    # Inicializar posiciones y colores
    posiciones_hexagonos = generar_posiciones_hex()
    colores_hexagonos = {pos: AMARILLO for pos in posiciones_hexagonos}
    
    last_hexagon = None  # Para rastrear el último hexágono sobre el que estuvo el ratón
    
    # Parámetros del botón "Hecho"
    ancho_boton = 120
    alto_boton = 50
    x_boton = (ANCHO - ancho_boton) // 2
    y_boton = ALTO - 100
    
    ejecutando_colmena = True
    while ejecutando_colmena:
        ventana.fill(BLANCO)
    
        for evento in pygame.event.get():
            if evento.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            elif evento.type == pygame.MOUSEBUTTONDOWN:
                if evento.button == 1:  # Botón izquierdo del ratón
                    if boton_clicado(evento.pos, x_boton, y_boton, ancho_boton, alto_boton):
                        # Generar clave robusta a partir del patrón
                        clave_robusta = generar_clave_desde_pattern(colores_hexagonos, posiciones_hexagonos)
                        ejecutando_colmena = False
                        return clave_robusta
                    else:
                        # Verificar si se hizo clic en algún hexágono
                        for (x_hex, y_hex) in posiciones_hexagonos:
                            if esta_dentro_hexagono(x_hex, y_hex, evento.pos):
                                # Cambiar de color el hexágono clicado
                                if colores_hexagonos[(x_hex, y_hex)] == AMARILLO:
                                    colores_hexagonos[(x_hex, y_hex)] = AZUL
                                else:
                                    colores_hexagonos[(x_hex, y_hex)] = AMARILLO
                                last_hexagon = (x_hex, y_hex)
                                break  # No es necesario seguir verificando otros hexágonos
            elif evento.type == pygame.MOUSEMOTION:
                if evento.buttons[0]:  # Si el botón izquierdo del ratón está presionado
                    pos_raton = evento.pos
                    for (x_hex, y_hex) in posiciones_hexagonos:
                        if esta_dentro_hexagono(x_hex, y_hex, pos_raton):
                            current_hexagon = (x_hex, y_hex)
                            if current_hexagon != last_hexagon:
                                # Cambiar de color el hexágono
                                if colores_hexagonos[current_hexagon] == AMARILLO:
                                    colores_hexagonos[current_hexagon] = AZUL
                                else:
                                    colores_hexagonos[current_hexagon] = AMARILLO
                                last_hexagon = current_hexagon
                            break
                    else:
                        # Si no está sobre ningún hexágono, resetear last_hexagon
                        last_hexagon = None
                else:
                    last_hexagon = None  # Si no se mantiene presionado el botón, resetear last_hexagon
    
        # Mostrar instrucciones
        fuente_texto = pygame.font.Font(None, 30)
        texto = fuente_texto.render("   Pinta una figura con el ratón coloreando los hexágonos", True, NEGRO)
        ventana.blit(texto, (10, 450))
    
        # Dibujar los hexágonos
        for (x_hex, y_hex) in posiciones_hexagonos:
            dibujar_hexagono(ventana, x_hex, y_hex, colores_hexagonos[(x_hex, y_hex)])
    
        # Dibujar el botón "Hecho" en el centro
        dibujar_boton(ventana, x_boton, y_boton, ancho_boton, alto_boton, "HECHO")
    
        # Dibujar el texto "GutiSoft 2024" en la esquina inferior derecha
        ventana.blit(texto_gutisoft, rect_texto)
    
        # Actualizar pantalla
        pygame.display.update()


# Bucle principal para volver al menú después de cada operación
while True:
    opcion = menu()

    if opcion == '1':  # Cifrar archivo
        clave_publica = cargar_clave_publica()
        if clave_publica:
            ruta_archivo = seleccionar_archivo(titulo="Seleccionar archivo a cifrar")  # Seleccionar archivo a cifrar

            if ruta_archivo:
                mensaje = cifrar_archivo(ruta_archivo, clave_publica)  # La función ya guarda el archivo
                ventana.fill(BLANCO)
                mostrar_texto(mensaje, 20, 100, color=AZUL_OSCURO, tamano_fuente=24)
                # Dibujar el texto "GutiSoft 2024"
                ventana.blit(texto_gutisoft, rect_texto)
                pygame.display.update()
                pygame.time.wait(5000)
                # No reiniciamos el script, simplemente continuamos
                continue
            else:
                ventana.fill(BLANCO)
                mostrar_texto("No se seleccionó un archivo para cifrar.", 20, 100, color=ROJO, tamano_fuente=24)
                # Dibujar el texto "GutiSoft 2024"
                ventana.blit(texto_gutisoft, rect_texto)
                pygame.display.update()
                pygame.time.wait(3000)
                # Continuar al menú principal
                continue
        else:
            # Si no se pudo cargar la clave pública, volvemos al menú principal
            continue

    elif opcion == '2':  # Descifrar archivo
        # Primero seleccionamos la clave privada cifrada y la desciframos con el pattern
        clave_privada = cargar_clave_privada_cifrada()

        if clave_privada:
            # Luego seleccionamos el archivo cifrado que nos enviaron
            ruta_archivo_cifrado = seleccionar_archivo(titulo="Seleccionar archivo cifrado")  # Seleccionar archivo cifrado

            if ruta_archivo_cifrado:
                try:
                    # Intentamos leer y procesar el archivo cifrado
                    with open(ruta_archivo_cifrado, 'r') as f:
                        datos_empaquetados = f.read()  # Leemos el contenido cifrado

                    # Descifrar el archivo (la función ya guarda el archivo descifrado)
                    mensaje = descifrar_archivo(datos_empaquetados, clave_privada, ruta_archivo_cifrado)
                    ventana.fill(BLANCO)
                    if "Error" in mensaje:
                        mostrar_texto(mensaje, 20, 100, color=ROJO, tamano_fuente=24)
                    else:
                        mostrar_texto(mensaje, 20, 100, color=AZUL_OSCURO, tamano_fuente=24)
                    # Dibujar el texto "GutiSoft 2024"
                    ventana.blit(texto_gutisoft, rect_texto)
                    pygame.display.update()
                    pygame.time.wait(5000)
                    # No reiniciamos el script, simplemente continuamos
                    continue
                except Exception as e:
                    # Si ocurre un error, mostramos un mensaje en la ventana
                    ventana.fill(BLANCO)
                    mostrar_texto("Error al descifrar el archivo.", 20, 100, color=ROJO, tamano_fuente=24)
                    mostrar_texto("Verifique que el archivo seleccionado es válido.", 20, 140, color=ROJO, tamano_fuente=24)
                    # Puedes mostrar detalles adicionales si lo deseas
                    # mostrar_texto(f"Detalle del error: {str(e)}", 20, 180, color=ROJO, tamano_fuente=24)
                    ventana.blit(texto_gutisoft, rect_texto)
                    pygame.display.update()
                    pygame.time.wait(5000)
                    # Continuar al menú principal
                    continue
            else:
                ventana.fill(BLANCO)
                mostrar_texto("No se seleccionó un archivo cifrado.", 20, 100, color=ROJO, tamano_fuente=24)
                # Dibujar el texto "GutiSoft 2024"
                ventana.blit(texto_gutisoft, rect_texto)
                pygame.display.update()
                pygame.time.wait(3000)
                # Continuar al menú principal
                continue
        else:
            # Si no se pudo cargar la clave privada, volvemos al menú principal
            continue

    elif opcion == '3':  # Generar claves
        mensaje = generar_guardar_claves()  # Solo aquí se genera la clave robusta y se cifra la clave privada
        ventana.fill(BLANCO)
        mostrar_texto(mensaje, 20, 100, color=AZUL_OSCURO, tamano_fuente=24)
        # Dibujar el texto "GutiSoft 2024"
        ventana.blit(texto_gutisoft, rect_texto)
        pygame.display.update()
        # Esperar un tiempo y luego volver al menú principal
        pygame.time.wait(5000)
        continue  # Volver al menú principal
