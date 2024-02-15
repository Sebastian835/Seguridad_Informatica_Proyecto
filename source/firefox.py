# Importar las bibliotecas necesarias
import sqlite3       # Biblioteca para interactuar con bases de datos SQLite
import pandas as pd  # Biblioteca para el manejo y análisis de datos

# Conectar a la base de datos SQLite que contiene las cookies de Firefox
fx = sqlite3.connect(
    "C:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\fmouarnu.default-release\\cookies.sqlite"
)

# Leer las cookies de la base de datos SQLite y almacenarlas en un DataFrame de Pandas
df_f = pd.read_sql_query("SELECT * from moz_cookies", fx)

# Función para calcular el número total de cookies en el DataFrame
def numero_total_cookies(df):
    numero_total_cookies = df.shape[0]  # Obtener el número de filas (cookies) en el DataFrame
    return numero_total_cookies

# Función para calcular el número total de páginas web únicas en el DataFrame
def numero_paginas_web(df):
    numero_paginas_web = df["host"].nunique()  # Contar el número de valores únicos en la columna "host", que identifica las páginas web
    return numero_paginas_web

# Función para encontrar las top 5 páginas web con más visitas
def top_paginas(df):
    # Contar las visitas para cada página y ordenarlas en orden descendente
    visitas_por_pagina = df["host"].value_counts().reset_index()
    # Renombrar las columnas para mayor claridad
    visitas_por_pagina.columns = ["Pagina", "Visitas"]
    # Seleccionar las primeras 5 páginas con más visitas
    top_5_paginas = visitas_por_pagina.head(5)
    return top_5_paginas


"""CODIGO QUE SEPA DIOS QUE HACE PERO FUNCIONA Y ESO ES LO QUE IMPORTA"""

# Importar las bibliotecas necesarias
import argparse     # Biblioteca para parsear argumentos de línea de comandos
import csv          # Biblioteca para leer y escribir archivos CSV
import ctypes as ct # Biblioteca para acceder a bibliotecas de C
import json         # Biblioteca para trabajar con JSON
import logging      # Biblioteca para generar registros de eventos
import locale       # Biblioteca para manejar configuraciones regionales
import os           # Biblioteca para realizar operaciones del sistema operativo
import platform     # Biblioteca para acceder a información sobre la plataforma del sistema
import sqlite3      # Biblioteca para interactuar con bases de datos SQLite
import sys          # Biblioteca que proporciona información sobre variables y funciones específicas de Python
import shutil       # Biblioteca para operaciones de copia de archivos
from base64 import b64decode  # Función para decodificar cadenas Base64
from getpass import getpass   # Función para obtener contraseñas de forma segura
from itertools import chain   # Función para iterar sobre secuencias de iterables
from subprocess import run, PIPE, DEVNULL  # Clase para ejecutar procesos secundarios
from urllib.parse import urlparse         # Función para analizar URL
from configparser import ConfigParser    # Biblioteca para trabajar con archivos de configuración INI
from typing import Optional, Iterator, Any  # Tipado opcional y tipos de iteradores

import pandas as pd  # Biblioteca para el manejo y análisis de datos con estructuras de datos DataFrame

# Configuración de registro
LOG: logging.Logger
VERBOSE = False

# Definir constantes y variables globales
SYSTEM = platform.system()
SYS64 = sys.maxsize > 2**32
DEFAULT_ENCODING = "utf-8"
PWStore = list[dict[str, str]]
__version_info__ = (1, 1, 0, "+git")
__version__: str = get_version()

# Definir excepciones personalizadas
class NotFoundError(Exception):
    """Excepción para manejar situaciones donde un archivo de credenciales no se encuentra"""
    pass

class Exit(Exception):
    """Excepción para permitir una salida limpia desde cualquier punto de ejecución"""
    # Códigos de salida para diferentes tipos de errores
    CLEAN = 0
    ERROR = 1
    MISSING_PROFILEINI = 2
    # (otros códigos de salida omitidos por brevedad)
    UNKNOWN_ERROR = 100
    KEYBOARD_INTERRUPT = 102

    def __init__(self, exitcode):
        self.exitcode = exitcode

    def __unicode__(self):
        return f"Premature program exit with exit code {self.exitcode}"

# Clase base para gestionar credenciales
class Credentials:
    """Gestor de backend de credenciales base"""
    def __init__(self, db):
        self.db = db

        # Configuración de registro
        LOG.debug("Ubicación de la base de datos: %s", self.db)
        if not os.path.isfile(db):
            raise NotFoundError(f"ERROR - {db} base de datos no encontrada\n")

        LOG.info("Utilizando %s para las credenciales.", db)

    def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
        pass

    def done(self):
        """Sobrescribir este método si la subclase de credenciales necesita realizar alguna acción después de la interacción"""
        pass

# Clase para gestionar credenciales en una base de datos SQLite
class SqliteCredentials(Credentials):
    """Gestor de backend de credenciales SQLite"""
    def __init__(self, profile):
        db = os.path.join(profile, "signons.sqlite")

        super(SqliteCredentials, self).__init__(db)

        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()

    def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
        LOG.debug("Leyendo base de datos de contraseñas en formato SQLite")
        self.c.execute(
            "SELECT hostname, encryptedUsername, encryptedPassword, encType "
            "FROM moz_logins"
        )
        for i in self.c:
            # produce hostname, encryptedUsername, encryptedPassword, encType
            yield i

    def done(self):
        """Cerrar el cursor de sqlite y la conexión de la base de datos"""
        super(SqliteCredentials, self).done()

        self.c.close()
        self.conn.close()

# Clase para gestionar credenciales en un archivo JSON
class JsonCredentials(Credentials):
    """Gestor de backend de credenciales JSON"""
    def __init__(self, profile):
        db = os.path.join(profile, "logins.json")

        super(JsonCredentials, self).__init__(db)

    def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
        with open(self.db) as fh:
            LOG.debug("Leyendo base de datos de contraseñas en formato JSON")
            data = json.load(fh)

            try:
                logins = data["logins"]
            except Exception:
                LOG.error(f"Formato no reconocido en {self.db}")
                raise Exit(Exit.BAD_SECRETS)

            for i in logins:
                try:
                    yield (
                        i["hostname"],
                        i["encryptedUsername"],
                        i["encryptedPassword"],
                        i["encType"],
                    )
                except KeyError:
                    # Esto debería manejar las contraseñas eliminadas que aún mantienen
                    # un registro en el archivo JSON - GitHub issue #99
                    LOG.info(f"Se omitió el registro {i} debido a campos faltantes")

# Función para localizar la biblioteca NSS en una de las muchas ubicaciones posibles
def find_nss(locations, nssname) -> ct.CDLL:
    """Localizar NSS en una de las muchas ubicaciones posibles"""
    fail_errors: list[tuple[str, str]] = []

    OS = ("Windows", "Darwin")

    for loc in locations:
        nsslib = os.path.join(loc, nssname)
        LOG.debug("Cargando biblioteca NSS desde %s", nsslib)

        if SYSTEM in OS:
            # En Windows, para encontrar las DLLs referenciadas por nss3.dll
            # necesitamos tener esas ubicaciones en PATH
            os.environ["PATH"] = ";".join([loc, os.environ["PATH"]])
            LOG.debug("PATH ahora es %s", os.environ["PATH"])
            # Sin embargo, esto no parece funcionar en todas las configuraciones y necesita
            # establecerse antes de comenzar Python, por lo que como solución alternativa cambiamos el directorio de trabajo
            # a la ubicación de nss3.dll/libnss3.dylib de Firefox
            if loc:
                if not os.path.isdir(loc):
                    # No tiene sentido intentar cargar desde ubicaciones que no existen
                    continue

                workdir = os.getcwd()
                os.chdir(loc)

        try:
            nss: ct.CDLL = ct.CDLL(nsslib)
        except OSError as e:
            fail_errors.append((nsslib, str(e)))
        else:
            LOG.debug("Biblioteca NSS cargada desde %s", nsslib)
            return nss
        finally:
            if SYSTEM in OS and loc:
                # Restaurar el directorio de trabajo cambiado anteriormente
                os.chdir(workdir)

    else:
        LOG.error(
            "No se pudo encontrar ni cargar '%s'. Esta biblioteca es esencial "
            "para interactuar con tu perfil de Mozilla.",
            nssname,
        )
        # (otros mensajes de error omitidos por brevedad)
        raise Exit(Exit.FAIL_LOCATE_NSS)


def load_libnss():
    """Cargar libnss en Python utilizando la interfaz CDLL"""
    if SYSTEM == "Windows":
        nssname = "nss3.dll"
        locations: list[str] = [
            "",  # Directorio actual o buscador de librerías del sistema
            os.path.expanduser("~\\AppData\\Local\\Mozilla Firefox"),
            os.path.expanduser("~\\AppData\\Local\\Firefox Developer Edition"),
            os.path.expanduser("~\\AppData\\Local\\Mozilla Thunderbird"),
            os.path.expanduser("~\\AppData\\Local\\Nightly"),
            os.path.expanduser("~\\AppData\\Local\\SeaMonkey"),
            os.path.expanduser("~\\AppData\\Local\\Waterfox"),
            "C:\\Program Files\\Mozilla Firefox",
            "C:\\Program Files\\Firefox Developer Edition",
            "C:\\Program Files\\Mozilla Thunderbird",
            "C:\\Program Files\\Nightly",
            "C:\\Program Files\\SeaMonkey",
            "C:\\Program Files\\Waterfox",
        ]
        if not SYS64:
            locations = [
                "",  # Directorio actual o buscador de librerías del sistema
                "C:\\Program Files (x86)\\Mozilla Firefox",
                "C:\\Program Files (x86)\\Firefox Developer Edition",
                "C:\\Program Files (x86)\\Mozilla Thunderbird",
                "C:\\Program Files (x86)\\Nightly",
                "C:\\Program Files (x86)\\SeaMonkey",
                "C:\\Program Files (x86)\\Waterfox",
            ] + locations

        # Si alguno de los softwares soportados está en PATH, intenta usarlo
        software = ["firefox", "thunderbird", "waterfox", "seamonkey"]
        for binary in software:
            location: Optional[str] = shutil.which(binary)
            if location is not None:
                nsslocation: str = os.path.join(os.path.dirname(location), nssname)
                locations.append(nsslocation)

    elif SYSTEM == "Darwin":
        nssname = "libnss3.dylib"
        locations = (
            "",  # Directorio actual o buscador de librerías del sistema
            "/usr/local/lib/nss",
            "/usr/local/lib",
            "/opt/local/lib/nss",
            "/sw/lib/firefox",
            "/sw/lib/mozilla",
            "/usr/local/opt/nss/lib",  # NSS instalado con Brew en Darwin
            "/opt/pkg/lib/nss",        # instalado a través de pkgsrc
            "/Applications/Firefox.app/Contents/MacOS",  # Ubicación de instalación manual predeterminada
            "/Applications/Thunderbird.app/Contents/MacOS",
            "/Applications/SeaMonkey.app/Contents/MacOS",
            "/Applications/Waterfox.app/Contents/MacOS",
        )

    else:
        nssname = "libnss3.so"
        if SYS64:
            locations = (
                "",  # Directorio actual o buscador de librerías del sistema
                "/usr/lib64",
                "/usr/lib64/nss",
                "/usr/lib",
                "/usr/lib/nss",
                "/usr/local/lib",
                "/usr/local/lib/nss",
                "/opt/local/lib",
                "/opt/local/lib/nss",
                os.path.expanduser("~/.nix-profile/lib"),
            )
        else:
            locations = (
                "",  # Directorio actual o buscador de librerías del sistema
                "/usr/lib",
                "/usr/lib/nss",
                "/usr/lib32",
                "/usr/lib32/nss",
                "/usr/lib64",
                "/usr/lib64/nss",
                "/usr/local/lib",
                "/usr/local/lib/nss",
                "/opt/local/lib",
                "/opt/local/lib/nss",
                os.path.expanduser("~/.nix-profile/lib"),
            )

    # Si esto tiene éxito, se cargó libnss
    return find_nss(locations, nssname)

class c_char_p_fromstr(ct.c_char_p):
    """Reemplazo de char_p de ctypes que maneja la codificación de str a bytes"""

    def from_param(self):
        return self.encode(DEFAULT_ENCODING)

class NSSProxy:
    class SECItem(ct.Structure):
        """estructura necesaria para interactuar con libnss"""

        _fields_ = [
            ("type", ct.c_uint),
            ("data", ct.c_char_p),  # en realidad: unsigned char *
            ("len", ct.c_uint),
        ]

        def decode_data(self):
            _bytes = ct.string_at(self.data, self.len)
            return _bytes.decode(DEFAULT_ENCODING)

    class PK11SlotInfo(ct.Structure):
        """Estructura opaca que representa un slot lógico PKCS"""

    def __init__(self, non_fatal_decryption=False):
        # Localizar libnss e intentar cargarla
        self.libnss = load_libnss()
        self.non_fatal_decryption = non_fatal_decryption

        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)

        self._set_ctypes(ct.c_int, "NSS_Init", c_char_p_fromstr)
        self._set_ctypes(ct.c_int, "NSS_Shutdown")
        self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_NeedLogin", SlotInfoPtr)
        self._set_ctypes(
            ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, c_char_p_fromstr
        )
        self._set_ctypes(
            ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p
        )
        self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)

        # para el manejo de errores
        self._set_ctypes(ct.c_int, "PORT_GetError")
        self._set_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self._set_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

    def _set_ctypes(self, restype, name, *argtypes):
        """Establecer tipos de entrada/salida en funciones C de libnss para conversión automática de tipos"""
        res = getattr(self.libnss, name)
        res.argtypes = argtypes
        res.restype = restype

        # Manejar la decodificación a cadena al devolver un c_char_p
        if restype == ct.c_char_p:

            def _decode(result, func, *args):
                try:
                    return result.decode(DEFAULT_ENCODING)
                except AttributeError:
                    return result

            res.errcheck = _decode

        setattr(self, "_" + name, res)

    def initialize(self, profile: str):
        # El prefijo sql: garantiza la compatibilidad con las bases de datos Berkley DB (cert8) y Sqlite (cert9)
        profile_path = "sql:" + profile
        LOG.debug("Inicializando NSS con perfil '%s'", profile_path)
        err_status: int = self._NSS_Init(profile_path)
        LOG.debug("NSS inicializado devolvió %s", err_status)

        if err_status:
            self.handle_error(
                Exit.FAIL_INIT_NSS,
                "No se pudo inicializar NSS, ¿quizás '%s' no es un perfil válido?",
                profile,
            )

    def shutdown(self):
        err_status: int = self._NSS_Shutdown()

        if err_status:
            self.handle_error(
                Exit.FAIL_SHUTDOWN_NSS,
                "No se pudo cerrar el perfil NSS actual",
            )

    def authenticate(self, profile, interactive):
        """Desbloquea el perfil si es necesario, en cuyo caso se solicitará una contraseña al usuario."""
        LOG.debug("Recuperando el slot de clave interna")
        keyslot = self._PK11_GetInternalKeySlot()

        LOG.debug("Slot de clave interna %s", keyslot)
        if not keyslot:
            self.handle_error(
                Exit.FAIL_NSS_KEYSLOT,
                "No se pudo recuperar el Slot de clave interna",
            )

        try:
            if self._PK11_NeedLogin(keyslot):
                password: str = ask_password(profile, interactive)

                LOG.debug("Autenticando con contraseña '%s'", password)
                err_status: int = self._PK11_CheckUserPassword(keyslot, password)

                LOG.debug("La comprobación de la contraseña de usuario devolvió %s", err_status)

                if err_status:
                    self.handle_error(
                        Exit.BAD_PRIMARY_PASSWORD,
                        "La contraseña principal no es correcta",
                    )

            else:
                LOG.info("No se encontró Contraseña Principal - no se necesita autenticación")
        finally:
            # Evitar fugas de PK11KeySlot
            self._PK11_FreeSlot(keyslot)

    def handle_error(self, exitcode: int, *logerror: Any):
        """Si ocurre un error en libnss, manejarlo e imprimir alguna información de depuración"""
        if logerror:
            LOG.error(*logerror)
        else:
            LOG.debug("Error durante una llamada a la biblioteca NSS, intentando obtener información de error")

        code = self._PORT_GetError()
        name = self._PR_ErrorToName(code)
        name = "NULL" if name is None else name
        # 0 es el idioma predeterminado (relacionado con la localización)
        text = self._PR_ErrorToString(code, 0)

        LOG.debug("%s: %s", name, text)

        raise Exit(exitcode)

    def decrypt(self, data64):
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)

        err_status: int = self._PK11SDR_Decrypt(inp, out, None)
        LOG.debug("La desencriptación de los datos devolvió %s", err_status)
        try:
            if err_status:  # -1 significa que la contraseña falló, otros estados son desconocidos
                error_msg = (
                    "La desencriptación de nombre de usuario/contraseña falló. "
                    "Credenciales dañadas o discrepancia en archivos de certificado/clave."
                )

                if self.non_fatal_decryption:
                    raise ValueError(error_msg)
                else:
                    self.handle_error(Exit.DECRYPTION_FAILED, error_msg)

            res = out.decode_data()
        finally:
            # Evitar fugas de SECItem
            self._SECITEM_ZfreeItem(out, 0)

        return res


class MozillaInteraction:
    """
    Interfaz de abstracción para el perfil de Mozilla y lib NSS
    """

    def __init__(self, non_fatal_decryption=False):
        self.profile = None
        self.proxy = NSSProxy(non_fatal_decryption)

    def load_profile(self, profile):
        """Inicializar la biblioteca NSS y el perfil"""
        self.profile = profile
        self.proxy.initialize(self.profile)

    def authenticate(self, interactive):
        """Autenticar que el perfil actual esté protegido por una contraseña principal,
        solicitar al usuario y desbloquear el perfil.
        """
        self.proxy.authenticate(self.profile, interactive)

    def unload_profile(self):
        """Cerrar NSS y desactivar el perfil actual"""
        self.proxy.shutdown()

    def decrypt_passwords(self) -> PWStore:
        """Descifrar el perfil solicitado usando la contraseña proporcionada.
        Devuelve todas las contraseñas en una lista de diccionarios
        """
        credentials: Credentials = self.obtain_credentials()

        LOG.info("Descifrando credenciales")
        outputs: PWStore = []

        url: str
        user: str
        passw: str
        enctype: int
        for url, user, passw, enctype in credentials:
            # enctype informa si las contraseñas necesitan ser descifradas
            if enctype:
                try:
                    LOG.debug("Descifrando datos de nombre de usuario '%s'", user)
                    user = self.proxy.decrypt(user)
                    LOG.debug("Descifrando datos de contraseña '%s'", passw)
                    passw = self.proxy.decrypt(passw)
                except (TypeError, ValueError) as e:
                    LOG.warning(
                        "No se pudo decodificar el nombre de usuario o la contraseña para la entrada de URL %s",
                        url,
                    )
                    LOG.debug(e, exc_info=True)
                    user = "*** falla de descifrado ***"
                    passw = "*** falla de descifrado ***"

            LOG.debug(
                "Nombre de usuario decodificado '%s' y contraseña '%s' para el sitio web '%s'",
                user,
                passw,
                url,
            )

            output = {"url": url, "user": user, "password": passw}
            outputs.append(output)

        if not outputs:
            LOG.warning("No se encontraron contraseñas en el perfil seleccionado")

        # Cerrar manejadores de credenciales (SQL)
        credentials.done()

        return outputs

    def obtain_credentials(self) -> Credentials:
        """Determinar cuál de los 2 motores de credenciales de backend posibles está disponible"""
        credentials: Credentials
        try:
            credentials = JsonCredentials(self.profile)
        except NotFoundError:
            try:
                credentials = SqliteCredentials(self.profile)
            except NotFoundError:
                LOG.error(
                    "No se pudo encontrar el archivo de credenciales (logins.json o signons.sqlite)."
                )
                raise Exit(Exit.MISSING_SECRETS)

        return credentials


class OutputFormat:
    def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
        self.pwstore = pwstore
        self.cmdargs = cmdargs

    def output(self):
        pass


class HumanOutputFormat(OutputFormat):
    def output(self):
        for output in self.pwstore:
            record: str = (
                f"\nSitio web:   {output['url']}\n"
                f"Nombre de usuario: '{output['user']}'\n"
                f"Contraseña: '{output['password']}'\n"
            )
            sys.stdout.write(record)


class JSONOutputFormat(OutputFormat):
    def output(self):
        return json.dumps(self.pwstore, indent=2)


class DataFrameOutputFormat(OutputFormat):
    def output(self):
        return pd.DataFrame(self.pwstore)


class CSVOutputFormat(OutputFormat):
    def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
        super().__init__(pwstore, cmdargs)
        self.delimiter = cmdargs.csv_delimiter
        self.quotechar = cmdargs.csv_quotechar
        self.header = cmdargs.csv_header

    def output(self):
        csv_writer = csv.DictWriter(
            sys.stdout,
            fieldnames=["url", "user", "password"],
            lineterminator="\n",
            delimiter=self.delimiter,
            quotechar=self.quotechar,
            quoting=csv.QUOTE_ALL,
        )
        if self.header:
            csv_writer.writeheader()

        for output in self.pwstore:
            csv_writer.writerow(output)


class TabularOutputFormat(CSVOutputFormat):
    def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
        super().__init__(pwstore, cmdargs)
        self.delimiter = "\t"
        self.quotechar = "'"


class PassOutputFormat(OutputFormat):
    def __init__(self, pwstore: PWStore, cmdargs: argparse.Namespace):
        super().__init__(pwstore, cmdargs)
        self.prefix = cmdargs.pass_prefix
        self.cmd = cmdargs.pass_cmd
        self.username_prefix = cmdargs.pass_username_prefix
        self.always_with_login = cmdargs.pass_always_with_login

    def output(self):
        self.test_pass_cmd()
        self.preprocess_outputs()
        self.export()

    def test_pass_cmd(self) -> None:
        """Verificar si 'pass' de passwordstore.org está instalado.
        Si está instalado pero no inicializado, inicialícelo.
        """
        LOG.debug("Probando si el almacén de contraseñas está instalado y configurado")

        try:
            p = run([self.cmd, "ls"], capture_output=True, text=True)
        except FileNotFoundError as e:
            if e.errno == 2:
                LOG.error("El almacén de contraseñas no está instalado y se solicitó la exportación.")
                raise Exit(Exit.PASSSTORE_MISSING)
            else:
                LOG.error("Ocurrió un error desconocido.")
                LOG.error("Error fue '%s'", e)
                raise Exit(Exit.UNKNOWN_ERROR)

        LOG.debug("pass devolvió:\nSalida estándar: %s\nError estándar: %s", p.stdout, p.stderr)

        if p.returncode != 0:
            if 'Try "pass init"' in p.stderr:
                LOG.error("El almacén de contraseñas no estaba inicializado.")
                LOG.error("Inicialice el almacén de contraseñas manualmente usando 'pass init'")
                raise Exit(Exit.PASSSTORE_NOT_INIT)
            else:
                LOG.error("Ocurrió un error desconocido al ejecutar 'pass'.")
                LOG.error("Salida estándar: %s\nError estándar: %s", p.stdout, p.stderr)
                raise Exit(Exit.UNKNOWN_ERROR)

    def preprocess_outputs(self):
        # El formato de "self.to_export" debería ser:
        #     {"dirección": {"login": "contraseña", ...}, ...}
        self.to_export: dict[str, dict[str, str]] = {}

        for record in self.pwstore:
            url = record["url"]
            user = record["user"]
            passw = record["password"]

            # Realizar un seguimiento de la dirección web, nombre de usuario y contraseñas
            # Si existen más de un nombre de usuario para la misma dirección web,
            # el nombre de usuario se usará como nombre del archivo
            address = urlparse(url)

            if address.netloc not in self.to_export:
                self.to_export[address.netloc] = {user: passw}

            else:
                self.to_export[address.netloc][user] = passw

    def export(self):
        """Exportar las contraseñas dadas al almacén de contraseñas

        El formato de "to_export" debería ser:
            {"dirección": {"login": "contraseña", ...}, ...}
        """
        LOG.info("Exportando credenciales al almacén de contraseñas")
        if self.prefix:
            prefix = f"{self.prefix}/"
        else:
            prefix = self.prefix

        LOG.debug("Usando prefijo pass '%s'", prefix)

        for address in self.to_export:
            for user, passw in self.to_export[address].items():
                # Cuando existen más de una cuenta para la misma dirección, agregue
                # el inicio de sesión al identificador de contraseña
                if self.always_with_login or len(self.to_export[address]) > 1:
                    passname = f"{prefix}{address}/{user}"
                else:
                    passname = f"{prefix}{address}"

                LOG.info("Exportando credenciales para '%s'", passname)

                data = f"{passw}\n{self.username_prefix}{user}\n"

                LOG.debug("Insertando pass '%s' '%s'", passname, data)

                # NOTA --force se utiliza. Las contraseñas existentes serán sobrescritas
                cmd: list[str] = [
                    self.cmd,
                    "insertar",
                    "--force",
                    "--multiline",
                    passname,
                ]

                LOG.debug("Ejecutando comando '%s' con stdin '%s'", cmd, data)

                p = run(cmd, input=data, capture_output=True, text=True)

                if p.returncode != 0:
                    LOG.error(
                        "ERROR: el almacén de contraseñas salió con un código distinto de cero: %s", p.returncode
                    )
                    LOG.error("Salida estándar: %s\nError estándar: %s", p.stdout, p.stderr)
                    raise Exit(Exit.PASSSTORE_ERROR)

                LOG.debug("Exportado correctamente '%s'", passname)


def get_sections(profiles):
    """
    Devuelve el hash de números de perfil y nombres de perfil.
    """
    sections = {}
    i = 1
    for section in profiles.sections():
        if section.startswith("Profile"):
            sections[str(i)] = profiles.get(section, "Path")
            i += 1
        else:
            continue
    return sections


def print_sections(sections, textIOWrapper=sys.stderr):
    """
    Imprime todas las secciones disponibles en un textIOWrapper (por defecto en sys.stderr)
    """
    for i in sorted(sections):
        textIOWrapper.write(f"{i} -> {sections[i]}\n")
    textIOWrapper.flush()


def ask_section(sections: ConfigParser):
    """
    Selecciona automáticamente el segundo perfil sin solicitar al usuario
    """
    # Suponiendo que sections es un objeto similar a un diccionario
    try:
        final_choice = sections["2"]
    except KeyError:
        LOG.error("¡El perfil N.° 2 no existe!")
        raise Exit(Exit.NO_SUCH_PROFILE)

    LOG.debug("Perfil seleccionado automáticamente: %s", final_choice)

    return final_choice


def ask_password(profile: str, interactive: bool) -> str:
    """
    Solicita la contraseña del perfil
    """
    passwd: str
    passmsg = f"\nContraseña principal para el perfil {profile}: "

    if sys.stdin.isatty() and interactive:
        passwd = getpass(passmsg)
    else:
        sys.stderr.write("Leyendo contraseña principal desde la entrada estándar:\n")
        sys.stderr.flush()
        # Capacidad de leer la contraseña desde stdin (echo "pass" | ./firefox_...)
        passwd = sys.stdin.readline().rstrip("\n")

    return passwd


def read_profiles(basepath):
    """
    Analiza los perfiles de Firefox en la ubicación proporcionada.
    Si list_profiles es verdadero, saldrá después de enumerar los perfiles disponibles.
    """
    profileini = os.path.join(basepath, "profiles.ini")

    LOG.debug("Leyendo perfiles desde %s", profileini)

    if not os.path.isfile(profileini):
        LOG.warning("profile.ini no encontrado en %s", basepath)
        raise Exit(Exit.MISSING_PROFILEINI)

    # Leer perfiles desde la carpeta de perfiles de Firefox
    profiles = ConfigParser()
    profiles.read(profileini, encoding=DEFAULT_ENCODING)

    LOG.debug("Perfiles leídos %s", profiles.sections())

    return profiles


def get_profile(
    basepath: str, interactive: bool, choice: Optional[str], list_profiles: bool
):
    """
    Selecciona el perfil a usar leyendo profiles.ini o asumiendo que la ruta dada ya es un perfil
    Si interactive es falso, no intentará preguntar qué perfil descifrar.
    choice contiene la opción que el usuario nos dio como un argumento de CLI.
    Si list_profiles es verdadero, saldrá después de enumerar todos los perfiles disponibles.
    """
    try:
        profiles: ConfigParser = read_profiles(basepath)

    except Exit as e:
        if e.exitcode == Exit.MISSING_PROFILEINI:
            LOG.warning("Continuando y asumiendo que '%s' es una ubicación de perfil", basepath)
            profile = basepath

            if list_profiles:
                LOG.error("No se permiten listar perfiles únicos.")
                raise

            if not os.path.isdir(profile):
                LOG.error("La ubicación del perfil '%s' no es un directorio", profile)
                raise
        else:
            raise
    else:
        if list_profiles:
            LOG.debug("Enumerando perfiles disponibles...")
            print_sections(get_sections(profiles), sys.stdout)
            raise Exit(Exit.CLEAN)

        sections = get_sections(profiles)

        if len(sections) == 1:
            section = sections["1"]

        elif choice is not None:
            try:
                section = sections[choice]
            except KeyError:
                LOG.error("¡El perfil N.° %s no existe!", choice)
                raise Exit(Exit.NO_SUCH_PROFILE)

        elif not interactive:
            LOG.error(
                "No sé qué perfil descifrar. "
                "Estamos en modo no interactivo y no se especificó -c/--choice."
            )
            raise Exit(Exit.MISSING_CHOICE)

        else:
            # Preguntar al usuario qué perfil abrir
            section = ask_section(sections)

        section = section
        profile = os.path.join(basepath, section)

        if not os.path.isdir(profile):
            LOG.error(
                "La ubicación del perfil '%s' no es un directorio. ¿Se ha manipulado profiles.ini?",
                profile,
            )
            raise Exit(Exit.BAD_PROFILEINI)

    return profile


class ConvertChoices(argparse.Action):
    """Acción argparse que interpreta el argumento `choices` como un dict
    mapeando los valores de opciones especificados por el usuario a los valores de opciones resultantes.
    """

    def __init__(self, *args, choices, **kwargs):
        super().__init__(*args, choices=choices.keys(), **kwargs)
        self.mapping = choices

    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, self.mapping[value])



def parse_sys_args() -> argparse.Namespace:
    """Analiza los argumentos de línea de comandos"""

    if SYSTEM == "Windows":
        profile_path = os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox")
    elif os.uname()[0] == "Darwin":
        profile_path = "~/Library/Application Support/Firefox"
    else:
        profile_path = "~/.mozilla/firefox"

    parser = argparse.ArgumentParser(
        description="Accede a perfiles de Firefox/Thunderbird y descifra las contraseñas existentes"
    )
    parser.add_argument(
        "profile",
        nargs="?",
        default=profile_path,
        help=f"Ruta a la carpeta del perfil (por defecto: {profile_path})",
    )

    format_choices = {
        "humano": HumanOutputFormat,
        "json": JSONOutputFormat,
        "csv": CSVOutputFormat,
        "tabular": TabularOutputFormat,
        "pass": PassOutputFormat,
        "dataframe": DataFrameOutputFormat,
    }

    parser.add_argument(
        "-f",
        "--formato",
        action=ConvertChoices,
        choices=format_choices,
        default=DataFrameOutputFormat,
        help="Formato para la salida.",
    )
    parser.add_argument(
        "-d",
        "--delimitador-csv",
        action="store",
        default=";",
        help="El delimitador para la salida CSV",
    )
    parser.add_argument(
        "-q",
        "--caracter-cita-csv",
        action="store",
        default='"',
        help="El carácter de cita para la salida CSV",
    )
    parser.add_argument(
        "--sin-cabecera-csv",
        action="store_false",
        dest="csv_header",
        default=True,
        help="No incluir una cabecera en la salida CSV.",
    )
    parser.add_argument(
        "--prefijo-usuario-pass",
        action="store",
        default="",
        help=(
            "Exportar nombre de usuario tal cual (por defecto), o con el prefijo de formato proporcionado. "
            "Por ejemplo, 'login: ' para browserpass."
        ),
    )
    parser.add_argument(
        "-p",
        "--prefijo-pass",
        action="store",
        default="web",
        help="Prefijo de carpeta para exportar a pass de passwordstore.org (por defecto: %(default)s)",
    )
    parser.add_argument(
        "-m",
        "--cmd-pass",
        action="store",
        default="pass",
        help="Comando/ruta a usar al exportar a pass (por defecto: %(default)s)",
    )
    parser.add_argument(
        "--siempre-con-login-pass",
        action="store_true",
        help="Guardar siempre como /<login> (por defecto: solo cuando hay múltiples cuentas por dominio)",
    )
    parser.add_argument(
        "-n",
        "--no-interactivo",
        action="store_false",
        dest="interactive",
        default=True,
        help="Deshabilitar la interactividad.",
    )
    parser.add_argument(
        "--no-descifrado-no-fatal",
        action="store_true",
        default=False,
        help="Si está configurado, las entradas dañadas se omitirán en lugar de abortar el proceso.",
    )
    parser.add_argument(
        "-c",
        "--eleccion",
        help="El perfil a usar (comienza con 1). Si hay solo un perfil, se establecerá automáticamente en ese.",
    )
    parser.add_argument(
        "-l", "--lista", action="store_true", help="Enumera los perfiles y sale."
    )
    parser.add_argument(
        "-e",
        "--codificacion",
        action="store",
        default=DEFAULT_ENCODING,
        help="Anular la codificación por defecto (%(default)s).",
    )
    parser.add_argument(
        "-v",
        "--detallado",
        action="count",
        default=0,
        help="Nivel de detalle. Advertencia en -vv (nivel más alto), la entrada del usuario se imprimirá en pantalla",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="Muestra la versión de firefox_decrypt y sale",
    )

    args = parser.parse_args()

    # entender `\t` como carácter de tabulación si se especifica como delimitador.
    if args.delimitador_csv == "\\t":
        args.delimitador_csv = "\t"

    return args


def setup_logging(args) -> None:
    """Configura el nivel de registro y configura el registro básico"""
    if args.detallado == 1:
        level = logging.INFO
    elif args.detallado >= 2:
        level = logging.DEBUG
    else:
        level = logging.WARN

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=level,
    )

    global LOG
    LOG = logging.getLogger(__name__)


def identify_system_locale() -> str:
    encoding: Optional[str] = locale.getpreferredencoding()

    if encoding is None:
        LOG.error(
            "No se pudo determinar qué codificación/locale usar para la interacción NSS. "
            "Esta configuración no es compatible.\n"
            "Si está en Linux o MacOS, busque en línea cómo configurar un locale compatible con UTF-8 e inténtelo de nuevo."
        )
        raise Exit(Exit.BAD_LOCALE)

    return encoding or "utf-8"



def main() -> None:
    """Punto de entrada principal"""
    args = parse_sys_args()

    setup_logging(args)

    global DEFAULT_ENCODING

    if args.encoding != DEFAULT_ENCODING:
        LOG.info(
            "Anulando la codificación por defecto de '%s' a '%s'",
            DEFAULT_ENCODING,
            args.encoding,
        )

        # Anular la codificación por defecto si está especificada por el usuario
        DEFAULT_ENCODING = args.encoding

    LOG.info("Ejecutando la versión de firefox_decrypt: %s", __version__)
    LOG.debug("Argumentos de línea de comandos analizados: %s", args)
    codificaciones = (
        ("stdin", sys.stdin.encoding),
        ("stdout", sys.stdout.encoding),
        ("stderr", sys.stderr.encoding),
        ("locale", identify_system_locale()),
    )

    LOG.debug(
        "Ejecutando con codificaciones: %s: %s, %s: %s, %s: %s, %s: %s", *chain(*codificaciones)
    )

    for flujo, codificacion in codificaciones:
        if codificacion.lower() != DEFAULT_ENCODING:
            LOG.warning(
                "Ejecutando con codificación no compatible '%s': %s"
                " - Es probable que las cosas fallen a partir de aquí",
                flujo,
                codificacion,
            )

    # Cargar perfil de Mozilla e inicializar NSS antes de solicitar la entrada del usuario
    moz = MozillaInteraction(args.non_fatal_decryption)

    basepath = os.path.expanduser(args.profile)

    # Leer perfiles de profiles.ini en la carpeta de perfil
    profile = get_profile(basepath, args.interactive, args.choice, args.list)

    # Iniciar NSS para el perfil seleccionado
    moz.load_profile(profile)
    # Comprobar si el perfil está protegido por contraseña y solicitar una contraseña
    moz.authenticate(args.interactive)
    # Decodificar todas las contraseñas
    outputs = moz.decrypt_passwords()

    # Exportar contraseñas en uno de muchos formatos
    formateador = args.formato(outputs, args)

    resultado = formateador.output()  # Obtener los datos en el formato especificado
    return resultado

    # Finalmente cerrar NSS
    moz.unload_profile()


def run_ffdecrypt():
    try:
        main()
    except KeyboardInterrupt:
        print("Salir.")
        sys.exit(Exit.KEYBOARD_INTERRUPT)
    except Exit as e:
        sys.exit(e.exitcode)


if __name__ == "__main__":
    run_ffdecrypt()