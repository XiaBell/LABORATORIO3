import argparse
from ftplib import FTP
import io
import os
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class ManejadorArchivoAes:
    """
    Gestiona la generación de llaves y las operaciones de cifrado/descifrado 
    utilizando el estándar AES en modo GCM (Galois/Counter Mode)
    """

    def __init__(self, archivoLlave: str = "secreto.key"):
        self.archivoLlave = archivoLlave
        self.llave = self.cargarOGenerarLlave()

    def cargarOGenerarLlave(self) -> bytes:
        """Carga una llave simétrica existente o genera una nueva de 256 bits."""
        if os.path.exists(self.archivoLlave):
            with open(self.archivoLlave, "rb") as archivoEntrada:
                return archivoEntrada.read()
        nuevaLlave = get_random_bytes(32)
        with open(self.archivoLlave, "wb") as archivoSalida:
            archivoSalida.write(nuevaLlave)
        return nuevaLlave

    def cifrarDatos(self, datos: bytes) -> bytes:
        """Aplica cifrado AES-GCM a un bloque de bytes y retorna Nonce + Tag + Cifrado."""
        cifrador = AES.new(self.llave, AES.MODE_GCM)
        textoCifrado, etiqueta = cifrador.encrypt_and_digest(datos)
        return cifrador.nonce + etiqueta + textoCifrado

    def descifrarDatos(self, datosCifrados: bytes) -> bytes:
        """Verifica la integridad y descifra un bloque de bytes usando AES-GCM."""
        if len(datosCifrados) < 32:
            raise ValueError("El archivo recibido no tiene un formato válido.")

        nonce = datosCifrados[:16]
        etiqueta = datosCifrados[16:32]
        textoCifrado = datosCifrados[32:]

        cifrador = AES.new(self.llave, AES.MODE_GCM, nonce=nonce)
        return cifrador.decrypt_and_verify(textoCifrado, etiqueta)

    def cifrarArchivo(self, rutaEntrada: str, rutaSalida: str) -> None:
        """Lee un archivo local, lo cifra y guarda el resultado en disco."""
        if not os.path.exists(rutaEntrada):
            raise FileNotFoundError(f"El archivo de entrada '{rutaEntrada}' no existe.")

        with open(rutaEntrada, "rb") as archivoEntrada:
            contenido = archivoEntrada.read()

        blobCifrado = self.cifrarDatos(contenido)
        with open(rutaSalida, "wb") as archivoSalida:
            archivoSalida.write(blobCifrado)

    def descifrarArchivo(self, rutaEntrada: str, rutaSalida: str) -> None:
        """Lee un archivo cifrado del disco, valida su integridad y lo descifra."""
        if not os.path.exists(rutaEntrada):
            raise FileNotFoundError(f"El archivo cifrado '{rutaEntrada}' no existe.")

        with open(rutaEntrada, "rb") as archivoEntrada:
            blobCifrado = archivoEntrada.read()

        contenidoOriginal = self.descifrarDatos(blobCifrado)
        with open(rutaSalida, "wb") as archivoSalida:
            archivoSalida.write(contenidoOriginal)


class ClienteFtpSeguro:
    """
    Cliente FTP adaptado para realizar transferencias seguras mediante
    el cifrado y descifrado de archivos directamente en memoria (RAM)
    """

    def __init__(
        self,
        host: str = "192.117.10.20",
        usuario: str = "ftpuser",
        password: str = "ftp123",
    ):
        self.host = host
        self.usuario = usuario
        self.password = password
        self.manejadorAes = ManejadorArchivoAes()

    def subirCifrado(self, rutaArchivoLocal: str, nombreRemoto: str = None) -> None:
        """Cifra un archivo local en memoria y lo transfiere al servidor FTP."""
        if not os.path.exists(rutaArchivoLocal):
            raise FileNotFoundError(f"El archivo local '{rutaArchivoLocal}' no existe.")

        if not nombreRemoto:
            nombreRemoto = f"{os.path.basename(rutaArchivoLocal)}.enc"

        with open(rutaArchivoLocal, "rb") as archivo:
            datosOriginales = archivo.read()

        datosCifrados = self.manejadorAes.cifrarDatos(datosOriginales)
        bufferMemoria = io.BytesIO(datosCifrados)

        print(f"[+] Conectando al servidor FTP {self.host} para subir el archivo...")
        with FTP() as ftp:
            ftp.connect(self.host)
            ftp.login(self.usuario, self.password)
            ftp.storbinary(f"STOR {nombreRemoto}", bufferMemoria)

        print(f"[+] Archivo cifrado subido exitosamente al FTP como '{nombreRemoto}'.")

    def bajarYDescifrar(self, nombreRemoto: str, rutaArchivoSalida: str) -> None:
        """Descarga un archivo cifrado del FTP a memoria, lo descifra y lo guarda."""
        bufferMemoria = io.BytesIO()

        print(f"[+] Conectando al servidor FTP {self.host} para descargar el archivo...")
        with FTP() as ftp:
            ftp.connect(self.host)
            ftp.login(self.usuario, self.password)
            ftp.retrbinary(f"RETR {nombreRemoto}", bufferMemoria.write)

        bufferMemoria.seek(0)
        datosCifrados = bufferMemoria.getvalue()
        datosDescifrados = self.manejadorAes.descifrarDatos(datosCifrados)

        with open(rutaArchivoSalida, "wb") as archivoSalida:
            archivoSalida.write(datosDescifrados)

        print(f"[+] Archivo descifrado y guardado exitosamente en '{rutaArchivoSalida}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gestor de cifrado AES-GCM y cliente FTP")
    parser.add_argument(
        "accion",
        choices=["enc", "dec", "subir", "bajar"],
        help="Acciones locales: 'enc', 'dec'. Acciones FTP: 'subir', 'bajar'",
    )
    parser.add_argument("entrada", help="Archivo de entrada (local o remoto)")
    parser.add_argument(
        "salida",
        nargs="?",
        default=None,
        help="Archivo de salida (opcional para 'subir')",
    )

    args = parser.parse_args()
    manejador = ManejadorArchivoAes()
    clienteFtp = ClienteFtpSeguro(host="192.117.10.20")

    try:
        if args.accion == "enc":
            if not args.salida:
                print("[-] Error: Requiere archivo de salida.", file=sys.stderr)
                sys.exit(1)
            manejador.cifrarArchivo(args.entrada, args.salida)
            print(f"[+] Archivo '{args.entrada}' cifrado con éxito en '{args.salida}'.")

        elif args.accion == "dec":
            if not args.salida:
                print("[-] Error: Requiere archivo de salida.", file=sys.stderr)
                sys.exit(1)
            manejador.descifrarArchivo(args.entrada, args.salida)
            print(f"[+] Archivo '{args.entrada}' descifrado con éxito en '{args.salida}'.")

        elif args.accion == "subir":
            clienteFtp.subirCifrado(args.entrada, args.salida)

        elif args.accion == "bajar":
            if not args.salida:
                print("[-] Error: Debes especificar el nombre local del archivo de salida.", file=sys.stderr)
                sys.exit(1)
            clienteFtp.bajarYDescifrar(args.entrada, args.salida)

    except (FileNotFoundError, ValueError, Exception) as error:
        print(f"[-] Error de operación: {error}", file=sys.stderr)
        sys.exit(1)