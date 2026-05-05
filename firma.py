import os # importa la libreria para interactuar con el sistema de archivos y rutas
from cryptography.hazmat.primitives import hashes, serialization # carga funciones para hashing y manejo de formatos de llaves
from cryptography.hazmat.primitives.asymmetric import rsa, padding # carga el algoritmo rsa y los metodos de relleno de seguridad
from cryptography.exceptions import InvalidSignature # importa la excepcion que se activa cuando una firma es falsa

def generar_llaves(): # define la funcion para crear el par de llaves rsa
    print("\n--- generar llaves ---") # imprime el encabezado de la seccion
# solicita la contraseña y la convierte a bytes para que sea procesable por la libreria
    passphrase = input("establece la contraseña para proteger tu llave privada: ").encode()
# captura el nombre base para nombrar los archivos resultantes de forma personalizada
    nombre_base = input("escribe un nombre para tus llaves ")

# genera una llave privada rsa con exponente publico 65537 y tamaño de 2048 bits
    llave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

# crea el nombre del archivo para la llave privada usando el nombre base elegido
    archivo_priv = f"{nombre_base}_privada.key"
# crea el nombre del archivo para la llave publica usando el nombre base elegido
    archivo_pub = f"{nombre_base}_publica.key"

# abre el archivo privado en modo escritura binaria para guardar los datos cifrados
    with open(archivo_priv, "wb") as f:
# guarda la llave privada en formato pem, encriptandola con la contraseña del usuario
        f.write(llave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        ))

# obtiene la llave publica a partir de la llave privada generada anteriormente
    llave_publica = llave_privada.public_key()
# abre el archivo publico en modo escritura binaria
    with open(archivo_pub, "wb") as f:
# guarda la llave publica en formato pem sin necesidad de contraseña
        f.write(llave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
# confirma al usuario los nombres exactos de los archivos creados en su carpeta
    print(f"\nllaves creadas con éxito:")
    print(f"- privada: {archivo_priv}")
    print(f"- pública: {archivo_pub}")

def firmar_archivo(): # define la funcion para generar la firma digital de un archivo
    print("\n--- firmar archivo ---") # imprime el encabezado de la seccion
# pide el nombre del archivo que se desea sellar digitalmente
    ruta_archivo = input("nombre del archivo a firmar: ")
# pide el nombre del archivo que contiene la llave privada necesaria para firmar
    ruta_llave = input("escribe el nombre de tu archivo de llave privada (.key): ")
# solicita la contraseña para desbloquear y cargar la llave privada en memoria
    passphrase = input("introduce la contraseña de la llave: ").encode()

    try: # inicia bloque de prueba para capturar errores de lectura o contraseña
# abre el archivo de la llave privada en modo lectura binaria
        with open(ruta_llave, "rb") as f:
# carga la llave privada usando la contraseña proporcionada por el usuario
            llave_privada = serialization.load_pem_private_key(
                f.read(),
                password=passphrase
            )

# abre el archivo que se va a firmar en modo lectura binaria
        with open(ruta_archivo, "rb") as f:
# lee todo el contenido del archivo para calcular su sello
            datos = f.read()

# genera la firma digital usando el algoritmo sha-256 y el esquema de relleno pss
        firma = llave_privada.sign(
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

# crea un archivo con el nombre original mas la extension .sig para guardar la firma
        with open(ruta_archivo + ".sig", "wb") as f:
            # escribe los bytes de la firma digital en el archivo de salida
            f.write(firma)
        
# informa que el proceso fue exitoso y muestra el nombre del archivo generado
        print(f"archivo firmado. se ha generado automáticamente: {ruta_archivo}.sig")

    except Exception as e: # captura fallos como archivos no encontrados o claves incorrectas
# muestra el mensaje de error para que el usuario sepa que fallo
        print(f"error: no se pudo firmar. revisa los nombres o la contraseña. ({e})")

def verificar_integridad(): # define la funcion para validar la firma sin pedir el archivo .sig
    print("\n--- verificar integridad ---") # imprime el encabezado de la seccion
# solicita el nombre del archivo que se quiere comprobar
    ruta_archivo = input("nombre del archivo original: ")
# solicita el nombre de la llave publica para realizar la validacion matematica
    ruta_publica = input("nombre de la llave pública: ")
    
# el programa construye automaticamente el nombre del archivo de firma agregando .sig
    ruta_firma = ruta_archivo + ".sig"

# usa la libreria os para verificar si el archivo de firma existe en la carpeta actual
    if not os.path.exists(ruta_firma):
# si no existe el archivo .sig, el programa detiene la ejecucion de esta funcion
        print(f"error: no se encontró el archivo de firma '{ruta_firma}'. ¿ya firmaste el archivo?")
        return

    try: # inicia bloque de prueba para la verificacion matematica
# abre y carga la llave publica desde su archivo correspondiente
        with open(ruta_publica, "rb") as f:
# lee el archivo pem y lo convierte en un objeto de llave publica usable
            llave_publica = serialization.load_pem_public_key(f.read())

# abre el archivo original para leer su contenido actual
        with open(ruta_archivo, "rb") as f:
# guarda el contenido del archivo en una variable para procesarlo
            datos = f.read()
# abre el archivo de firma detectado automaticamente por el programa
        with open(ruta_firma, "rb") as f:
# lee los bytes de la firma para compararlos con el archivo original
            firma = f.read()

# la llave publica intenta validar la firma usando rsa, sha-256 y relleno pss
        llave_publica.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
# si la linea anterior no lanza un error, significa que la firma es correcta
        print(f"buscando firma: {ruta_firma}")
        print("la firma es válida. el archivo no ha sido alterado.")

    except InvalidSignature: # esta excepcion se dispara si los datos del archivo cambiaron
# informa que se encontro la firma pero que el contenido del archivo ya no coincide
        print(f"buscando firma: {ruta_firma}")
        print("la firma es inválida. el archivo ha sido modificado.")
    except Exception as e: # captura otros errores como archivos de llave dañados
# imprime el error tecnico para diagnostico
        print(f"error: {e}")

def menu(): # define la funcion principal que muestra las opciones en pantalla
# inicia un bucle infinito para que el usuario pueda hacer varias acciones seguidas
    while True:
# muestra las opciones de texto en la terminal
        print("\n=== sistema de firma ===")
        print("1. generar llaves personalizadas")
        print("2. firmar un archivo")
        print("3. verificar")
        print("4. salir")
# captura la eleccion numerica del usuario
        op = input("selecciona una opción: ")

# estructura condicional para llamar a la funcion elegida por el usuario
        if op == "1": generar_llaves() # llama a la creacion de llaves
        elif op == "2": firmar_archivo() # llama a la creacion de firma
        elif op == "3": verificar_integridad() # llama a la validacion de integridad
        elif op == "4": break # rompe el bucle while y cierra el programa

if __name__ == "__main__":
    
    menu()