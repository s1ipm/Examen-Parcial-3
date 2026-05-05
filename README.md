# Examen Parcial 3

## Sistema de Firma Digital

Implementa un flujo de trabajo para garantizar la integridad y autenticidad de documentos mediante el uso de algoritmos asimétricos RSA y funciones de dispersión SHA-256. A diferencia de una simulación básica, este sistema utiliza estándares criptográficos reales para asegurar que cualquier modificación en los datos sea detectada de forma inmediata.

El primer enfoque utilizando únicamente las librerías hashlib y os presentaba limitaciones críticas que impedían una validación real. En ese modelo, el sistema solo funcionaba como una bitácora de archivos: confirmaba que los archivos existían, pero no podía probar matemáticamente que el contenido no había sido alterado por un tercero. La contraseña se guardaba de forma visible en los archivos, lo que invalidaba cualquier principio de seguridad.

La modificación hacia la librería cryptography fue necesaria para transformar el script en una herramienta profesional. Esta librería no solo resume el archivo, sino que crea un vínculo matemático entre el autor y el documento.

#### Importancia de la Librería Cryptography
El uso de esta librería es lo que permite que el sistema realmente funcione bajo los estándares de ciberseguridad actuales:

- Cifrado de Llaves en Reposo: A diferencia de la versión anterior, la contraseña del usuario se utiliza para encriptar la llave privada mediante el estándar AES antes de guardarla en el disco. Esto garantiza que si el archivo .key es robado, su contenido es ilegible sin la clave.

- Algoritmo RSA de 2048 bits: Implementa matemáticas de números primos para generar un par de llaves vinculadas. Lo que se firma con la llave privada solo puede ser validado por su llave pública correspondiente.

- Esquema de Relleno PSS: Añade una capa de seguridad probabilística a la firma, evitando ataques de repetición y asegurando que la verificación sea extremadamente sensible a cualquier cambio en los bits del archivo original.

#### Análisis del Funcionamiento

1. Gestión de Identidad Profesional

El proceso genera llaves en formato PEM. El programa solicita un nombre base para personalizar los archivos, permitiendo al usuario identificar claramente su identidad digital. La llave privada se protege con una capa de cifrado PKCS8, mientras que la pública queda disponible para la distribución.

2. Procesamiento del Hash y Firma Digital

Al sellar un documento, el sistema lee el archivo en modo binario ("rb"). Esto es vital para capturar la estructura exacta de los datos. Se genera un hash SHA-256 que actúa como la huella digital del archivo. Posteriormente, la llave privada "firma" este hash, generando un sello único e irrepetible que se guarda en el archivo .sig.

3. Verificación Automática de Integridad
   
La función de verificación fue optimizada para realizar una detección automática. Al ingresar el nombre del archivo original, el programa busca por cuenta propia el rastro digital (.sig).

La importancia de este paso reside en la validación matemática: el programa recupera el hash de la firma usando la llave pública y lo compara contra el hash actual del archivo en el disco. Si el archivo fue editado y guardado, los hashes serán diferentes y el sistema lanzará una excepción de firma inválida, cumpliendo así el objetivo de proteger la integridad de la información.

_hashes.SHA256:_ Algoritmo matemático que reduce cualquier archivo a una huella única de longitud fija.

_padding.PSS:_ Método de relleno que asegura que la firma RSA sea segura y resistente a ataques de análisis de datos.

_serialization:_ Proceso que convierte las llaves matemáticas en archivos físicos que pueden ser almacenados y cargados por el sistema.

_"rb" / "wb":_ Modos de apertura binaria que permiten manejar los bytes de las llaves y las firmas sin que el sistema operativo altere su contenido al interpretarlos como texto.
