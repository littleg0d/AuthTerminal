import pyotp
import json
import colorama
import time
import os
import sys
import getpass
import base64
from datetime import datetime
from urllib.parse import urlparse, parse_qs


from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

JSON_FILE = 'secrets.json'
colorama.init(autoreset=True)



def limpiar_pantalla():
    os.system('cls' if os.name == 'nt' else 'clear')


def parse_otpauth_uri(uri):
    try:
        parsed_uri = urlparse(uri)
        params = parse_qs(parsed_uri.query)
        secreto = params['secret'][0]
        etiqueta = parsed_uri.path.lstrip('/').split(':')
        issuer = params.get('issuer', [''])[0]
        nombre_cuenta = issuer
        label_user_part = etiqueta[-1]
        if label_user_part and (issuer.lower() not in label_user_part.lower()):
            nombre_cuenta += f" ({label_user_part})"
        if not nombre_cuenta:
            nombre_cuenta = "/".join(etiqueta)
        return {'nombre': nombre_cuenta.strip(), 'secreto': secreto}
    except (KeyError, IndexError):
        return None



def derivar_clave(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def pedir_password(confirmar=False):
    password = getpass.getpass("Introduce tu contraseña maestra: ")
    if not password:
        print("La contraseña no puede estar vacía.")
        sys.exit(1)
    if confirmar:
        password_conf = getpass.getpass("Confirma la contraseña maestra: ")
        if password != password_conf:
            print("Las contraseñas no coinciden.")
            sys.exit(1)
    return password


def cargar_y_descifrar(password: str):
    try:
        with open(JSON_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        salt = base64.urlsafe_b64decode(data['salt'])
        datos_cifrados = data['data'].encode()
        clave = derivar_clave(password.encode(), salt)
        f = Fernet(clave)
        datos_descifrados = f.decrypt(datos_cifrados)
        return json.loads(datos_descifrados.decode())
    except FileNotFoundError:
        print(f"No se encontró el archivo '{JSON_FILE}'.")
        print("Debes importar cuentas primero para crearlo.")
        return None
    except (InvalidToken, KeyError, TypeError):
        print(f"\033[1;31mContraseña maestra incorrecta o archivo '{JSON_FILE}' corrupto.\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"Ocurrió un error inesperado al cargar: {e}")
        sys.exit(1)


def cifrar_y_guardar(cuentas: list, password: str):
    try:
        salt = os.urandom(16)
        clave = derivar_clave(password.encode(), salt)
        f = Fernet(clave)
        datos_json_bytes = json.dumps(cuentas, indent=4, ensure_ascii=False).encode()
        datos_cifrados = f.encrypt(datos_json_bytes)
        data_para_guardar = {
            'salt': base64.urlsafe_b64encode(salt).decode(),
            'data': datos_cifrados.decode()
        }
        with open(JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(data_para_guardar, f, indent=4)
        return True
    except Exception as e:
        print(f"Ocurrió un error al cifrar y guardar: {e}")
        return False



def modo_importacion(archivo_txt, cuentas_existentes: list):
    """Importa cuentas a la lista 'cuentas_existentes'."""
    print(f"Iniciando importación desde '{archivo_txt}'...")
    if not os.path.exists(archivo_txt):
        print(f"Error: El archivo de importación '{archivo_txt}' no existe.")
        return False
    secretos_existentes = {cuenta['secreto'] for cuenta in cuentas_existentes}
    cuentas_nuevas = 0
    duplicados = 0
    hubo_cambios = False
    with open(archivo_txt, 'r', encoding='utf-8') as f:
        for linea in f:
            linea = linea.strip()
            if not linea or linea.startswith('#'):
                continue
            nueva_cuenta = parse_otpauth_uri(linea)
            if nueva_cuenta:
                if nueva_cuenta['secreto'] not in secretos_existentes:
                    cuentas_existentes.append(nueva_cuenta)
                    secretos_existentes.add(nueva_cuenta['secreto'])
                    cuentas_nuevas += 1
                    hubo_cambios = True
                    print(f"  [+] Añadido: {nueva_cuenta['nombre']}")
                else:
                    duplicados += 1
                    print(f"  [!] Omitido (duplicado): {nueva_cuenta['nombre']}")
            else:
                print(f"  [!] Advertencia: Línea mal formada ignorada: {linea[:30]}...")
    print("\n--- Resumen de la Importación ---")
    print(f"Cuentas nuevas añadidas: {cuentas_nuevas}")
    print(f"Cuentas duplicadas omitidas: {duplicados}")
    print(f"Total de cuentas ahora: {len(cuentas_existentes)}")
    return hubo_cambios


def modo_visualizacion(cuentas: list):
    """Muestra los códigos TOTP"""

    if not cuentas:
        print(f"No se encontraron cuentas en '{JSON_FILE}'.")
        print("\nPuedes añadir cuentas ejecutando el script en modo de importación:")
        print(f"  python {sys.argv[0]} importar mi_archivo.txt")
        return

    try:
        # Añadimos +2 para un pequeño margen
        max_len_nombre = max(len(cuenta['nombre']) for cuenta in cuentas) + 2
    except ValueError:
        max_len_nombre = 35  # Fallback por si la lista está vacía

    try:
        while True:
            limpiar_pantalla()
            print(f"--- Tus Códigos de Autenticación (archivo: {JSON_FILE} [CIFRADO]) ---")
            print(f"Actualizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

            for cuenta in cuentas:
                try:
                    totp = pyotp.TOTP(cuenta['secreto'])
                    codigo_actual = totp.now()
                    codigo_formateado = f"{codigo_actual[:3]} {codigo_actual[3:]}"
                    print(f"{cuenta['nombre']:<{max_len_nombre}} ->   \033[1;32m{codigo_formateado}\033[0m")
                except Exception:
                    print(
                        f"{cuenta.get('nombre', 'N/A'):<{max_len_nombre}} ->   \033[1;31mError al generar código\033[0m")

            print("\n" + "-" * (max_len_nombre + 20))
            tiempo_restante = 30 - (int(time.time()) % 30)
            barra_progreso = '█' * tiempo_restante + '░' * (30 - tiempo_restante)
            print(f"Nuevos códigos en {tiempo_restante:2d}s [{barra_progreso}]")
            print("\nPresiona Ctrl+C para salir.")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\nCerrando Auth.")


def modo_cambiar_password():
    """Permite al usuario cambiar la contraseña maestra."""
    print("--- Cambiar Contraseña Maestra ---")
    if not os.path.exists(JSON_FILE):
        print(f"No existe el archivo '{JSON_FILE}'. No hay contraseña que cambiar.")
        print("Ejecuta el modo 'importar' primero.")
        sys.exit(0)

    print("Primero, introduce tu contraseña actual.")
    password_actual = pedir_password(confirmar=False)
    cuentas = cargar_y_descifrar(password_actual)



    print("\033[1;32mContraseña actual correcta.\033[0m")


    print("\nAhora, introduce la nueva contraseña maestra.")
    nueva_password = pedir_password(confirmar=True)


    print("\nVolviendo a cifrar y guardando la bóveda con la nueva contraseña...")
    if cifrar_y_guardar(cuentas, nueva_password):
        print("\033[1;32m¡Contraseña cambiada exitosamente!\033[0m")
    else:
        print("\033[1;31mError: No se pudo guardar la bóveda con la nueva contraseña.\033[0m")




def main():
    """Controla el flujo principal y decide qué modo ejecutar."""

    es_primera_vez = not os.path.exists(JSON_FILE)


    comando = 'visualizar'
    archivo_importacion = None


    if len(sys.argv) == 2 and sys.argv[1].lower() == 'cambiarpass':
        comando = 'cambiarpass'
    elif len(sys.argv) == 3 and sys.argv[1].lower() == 'importar':
        comando = 'importar'
        archivo_importacion = sys.argv[2]
    elif len(sys.argv) != 1:
        print("Uso incorrecto.")
        print(f"Para ver los códigos:  python {sys.argv[0]}")
        print(f"Para importar:        python {sys.argv[0]} importar <archivo.txt>")
        print(f"Para cambiar pass:    python {sys.argv[0]} cambiarpass")
        sys.exit(1)




    if es_primera_vez:

        if comando == 'visualizar':
            print(f"No existe el archivo '{JSON_FILE}'.")
            print("Debes importar cuentas primero para crear tu bóveda cifrada.")
            print(f"Ejecuta: python {sys.argv[0]} importar <tu_archivo.txt>")
            sys.exit(0)
        elif comando == 'cambiarpass':
            print(f"No existe el archivo '{JSON_FILE}'. No hay contraseña que cambiar.")
            print("Ejecuta el modo 'importar' primero.")
            sys.exit(0)


        elif comando == 'importar':
            print(f"Bienvenido. Creando una nueva bóveda cifrada en '{JSON_FILE}'...")
            print("Por favor, crea una contraseña maestra. ¡No la pierdas!")
            password = pedir_password(confirmar=True)
            cuentas = []  # Empezamos con una lista vacía
            hubo_cambios = modo_importacion(archivo_importacion, cuentas)

            if hubo_cambios:
                print(f"\nGuardando y cifrando bóveda en '{JSON_FILE}'...")
                if cifrar_y_guardar(cuentas, password):
                    print("¡Bóveda creada y guardada exitosamente!")
                else:
                    print("Error: No se pudo guardar la bóveda.")
            else:
                print("No se importó ninguna cuenta nueva. No se creó el archivo.")

    else:


        if comando == 'cambiarpass':
            modo_cambiar_password()
            sys.exit(0)



        password = pedir_password(confirmar=False)
        cuentas = cargar_y_descifrar(password)

        if comando == 'visualizar':
            modo_visualizacion(cuentas)

        elif comando == 'importar':
            hubo_cambios = modo_importacion(archivo_importacion, cuentas)
            if hubo_cambios:
                print(f"\nGuardando y cifrando cambios en '{JSON_FILE}'...")
                if cifrar_y_guardar(cuentas, password):
                    print("¡Cambios guardados exitosamente!")
                else:
                    print("Error: No se pudieron guardar los cambios.")
            else:
                print("\nNo hubo cambios que guardar.")


if __name__ == "__main__":
    main()