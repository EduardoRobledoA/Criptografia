from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import streamlit as st
import base64
import scrypt
import os

st.set_page_config(
    page_title="XS",
    page_icon=":cyclone:",
    layout="wide",  
    initial_sidebar_state="collapsed"
)

global generaConexionUserA, generaConexionUserB
generaConexionUserA = False
generaConexionUserB = False

if 'estado' not in st.session_state:
    st.session_state.estado = False

def encriptarMensajeAES(llave, mensaje):
    cifrado = AES.new(llave, AES.MODE_EAX)
    nonce = cifrado.nonce
    textoCifrado, tag = cifrado.encrypt_and_digest(mensaje)
    return nonce, textoCifrado, tag

def desencriptarMensajeAES(nonce, llave, textoCifrado, tag):
    cifrado = AES.new(llave, AES.MODE_EAX, nonce=nonce)
    textoPlano = cifrado.decrypt(textoCifrado)
    try:
        cifrado.verify(tag)
        return textoPlano
    except ValueError:
        return False

def RSAEncriptarKEM(llavePublicaUsuario, llaveSimetrica):
    cifradoRSA = PKCS1_OAEP.new(RSA.importKey(llavePublicaUsuario))
    llaveCifrada = cifradoRSA.encrypt(llaveSimetrica)
    return llaveCifrada

def RSADesencriptarKEM(llavePrivadaUsuario, llaveCifrada):
    cifradoRSA = PKCS1_OAEP.new(RSA.importKey(llavePrivadaUsuario))
    llave = cifradoRSA.decrypt(llaveCifrada)
    return llave

def cifradoSinFirma(sinFirmaUsuarioA, sinFirmaUsuarioB, llaveSesion, llavePublicaUsuarioAPEM, llavePrivadaUsuarioBPEM, llavePublicaUsuarioBPEM, llavePrivadaUsuarioAPEM):
    sinFirmaUsuarioA.markdown('## Usuario A')
    mensajeUserA = sinFirmaUsuarioA.text_input('Mensaje para usuario B:')

    sinFirmaUsuarioB.markdown('## Usuario B')
    mensajeUserB = sinFirmaUsuarioB.text_input('Mensaje para usuario A:')

    if mensajeUserA != "":
        nonceA, ciphertextA, tagA = encriptarMensajeAES(llaveSesion, mensajeUserA.encode())
        llaveSesionEncriptadaParaB = RSAEncriptarKEM(llavePublicaUsuarioBPEM, llaveSesion)
        sinFirmaUsuarioB.text_area("Mensaje recibido", 'B: ' + desencriptarMensajeAES(nonceA, RSADesencriptarKEM(llavePrivadaUsuarioBPEM, llaveSesionEncriptadaParaB), 
                                                                ciphertextA, tagA).decode(), height=10, disabled=True)

    if mensajeUserB != "":
        nonceB, ciphertextB, tagB = encriptarMensajeAES(llaveSesion, mensajeUserB.encode())
        llaveSesionEncriptadaParaA = RSAEncriptarKEM(llavePublicaUsuarioAPEM, llaveSesion)
        sinFirmaUsuarioA.text_area("Mensaje recibido", 'A: ' + desencriptarMensajeAES(nonceB, RSADesencriptarKEM(llavePrivadaUsuarioAPEM, llaveSesionEncriptadaParaA),
                                                                    ciphertextB, tagB).decode(), height=10, disabled=True)

def cifradoConFirma(conFirmaUsuarioA, conFirmaUsuarioB, llavePublicaUsuarioAPEM, llavePublicaUsuarioBPEM, llavePrivadaUsuarioAPEM, llavePrivadaUsuarioBPEM):
    conFirmaUsuarioA.markdown('## Usuario A')
    mensajeUserA = conFirmaUsuarioA.text_input('Mensaje firmado para usuario B:')

    conFirmaUsuarioB.markdown('## Usuario B')
    mensajeUserB = conFirmaUsuarioB.text_input('Mensaje firmado para usuario A:')

    if mensajeUserA != "":
        llaveImportadaUsuarioA = RSA.import_key(llavePrivadaUsuarioAPEM)
        hash = SHA256.new(mensajeUserA.encode())
        firma = PKCS115_SigScheme(llaveImportadaUsuarioA)
        firmaUsuarioA = firma.sign(hash)
        llavePublicaUsuarioAPEM = RSA.import_key(llavePublicaUsuarioAPEM)
        verificaUsuarioA = PKCS115_SigScheme(llavePublicaUsuarioAPEM)

        try:
            verificaUsuarioA.verify(hash, firmaUsuarioA)
            conFirmaUsuarioB.write('La firma del usuario A es válida.')
        except (ValueError, TypeError):
            conFirmaUsuarioB.write('La firma no es válida.')

    if mensajeUserB != "":
        llaveImportadaUsuarioB = RSA.import_key(llavePrivadaUsuarioBPEM)
        hash = SHA256.new(mensajeUserA.encode())
        firma = PKCS115_SigScheme(llaveImportadaUsuarioB)
        firmaUsuarioB = firma.sign(hash)
        llavePublicaUsuarioAPEM = RSA.import_key(llavePublicaUsuarioBPEM)
        verificaUsuarioB = PKCS115_SigScheme(llavePublicaUsuarioAPEM)

        try:
            verificaUsuarioB.verify(hash, firmaUsuarioB)
            conFirmaUsuarioA.write('La firma del usuario B es válida.')
        except (ValueError, TypeError):
            conFirmaUsuarioA.write('La firma no es válida.')

def generarSalt():
    salt = os.urandom(16)
    return salt

def cifradoLlaveSimetricaSalt(secreto):
    saltSesion = generarSalt()
    secretoCodificado = secreto
    secretoCompartido = scrypt.hash(secretoCodificado, saltSesion, 2048, 8, 1, 32) #256 bits
    return secretoCompartido

def crearLlavesRSA(contraPrivada):
    llavesParesUsuario = RSA.generate(2048)
    llavePublicaUsuario = llavesParesUsuario.publickey()
    llavePublicaUsuarioPEM = llavePublicaUsuario.exportKey('PEM')
    llavePrivadaUsuarioPEM = llavesParesUsuario.exportKey('PEM',contraPrivada)

    return llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM

def descargaLLavesUsuario(llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM, llavesUsuario, usuario):
    if usuario == 'A':
        llavesUsuario.download_button('Descargar clave pública usuario A', llavePublicaUsuarioPEM, 'llavePublicaUsuarioA.pem')
        llavesUsuario.download_button('Descargar clave privada usuario A', llavePrivadaUsuarioPEM, 'llavePrivadaUsuarioA.pem')
    
    if usuario == 'B':
        llavesUsuario.download_button('Descargar clave pública usuario B', llavePublicaUsuarioPEM, 'llavePublicaUsuarioB.pem')
        llavesUsuario.download_button('Descargar clave privada usuario B', llavePrivadaUsuarioPEM, 'llavePrivadaUsuarioB.pem')

def cifradoSecretoAsimetrica(llavePublicaUsuario, secreto):
    cifradoRSA = PKCS1_OAEP.new(RSA.import_key(llavePublicaUsuario.getvalue()))
    secretoCifrado = cifradoRSA.encrypt(secreto.encode())
    return secretoCifrado

def descifradoSecretoAsimetrica(secretoCifrado, columna):
    llavePrivadaUsuarioPEM = columna.file_uploader('Sube tu clave privada', type=['pem'])
    contraPriva = columna.text_input("Inserta tu contraseña para la llave privada:")
    if llavePrivadaUsuarioPEM is not None and contraPriva != "" and len(contraPriva)>=8:
        cifradoRSA = PKCS1_OAEP.new(RSA.import_key(llavePrivadaUsuarioPEM.getvalue(), contraPriva))
        secreto = cifradoRSA.decrypt(secretoCifrado)
        return secreto

def actualizaAvance():
    st.session_state.estado = True

def compartirSecreto():
    global generaConexionUserA, generaConexionUserB

    if st.session_state.estado == False:
        st.title('Protocolo de intercambio de mensajes seguro')

        usuario = st.selectbox('Selecciona el usuario que deseas simular:', ('Usuario A', 'Usuario B'))

        if 'Usuario A' == usuario:
            indicacionLlavesUsuarioA = st.toggle("Genera llaves para usuario A")

            if indicacionLlavesUsuarioA:
                contraPrivada = st.text_input("Inserta tu contraseña para la llave privada:")
                if contraPrivada != "" and len(contraPrivada)>=8:
                    llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM = crearLlavesRSA(contraPrivada)
                    descargaLLavesUsuario(llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM, st, 'A')

            else:
                secreto = st.text_input('A - Inserta el secreto:')
                llavePublicaUsuarioBPEM = st.file_uploader('Sube la clave pública usuario B', type=['pem'])

                if secreto != "" and llavePublicaUsuarioBPEM is not None:
                    secretoCifrado = cifradoSecretoAsimetrica(llavePublicaUsuarioBPEM, secreto)
                    generaConexionUserA = True
                    generaConexionUserB = False

        if 'Usuario B' == usuario:
            indicacionLlavesUsuarioB = st.toggle("Genera llaves para usuario B")

            if indicacionLlavesUsuarioB:
                contraPrivada = st.text_input("Inserta tu contraseña para la llave privada:")
                if contraPrivada != "" and len(contraPrivada)>=8:
                    llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM = crearLlavesRSA(contraPrivada)
                    descargaLLavesUsuario(llavePublicaUsuarioPEM, llavePrivadaUsuarioPEM, st, 'B')

            else:
                secreto = st.text_input('B - Inserta el secreto:')
                llavePublicaUsuarioAPEM = st.file_uploader('Sube la clave pública usuario A', type=['pem'])

                if secreto != "" and llavePublicaUsuarioAPEM is not None:
                    secretoCifrado = cifradoSecretoAsimetrica(llavePublicaUsuarioAPEM, secreto)
                    generaConexionUserB = True
                    generaConexionUserA = False


        usuarioA, usuarioB = st.columns(2)

        if generaConexionUserA and secretoCifrado != "":
            usuarioB.markdown('## Usuario B')
            secretoRecibido = descifradoSecretoAsimetrica(secretoCifrado, usuarioB)
            if secretoRecibido is not None:
                iniciaChatLlave = cifradoLlaveSimetricaSalt(secretoRecibido)
                if iniciaChatLlave is not None:
                    usuarioB.button('Iniciar chat', on_click=actualizaAvance)

        if generaConexionUserB and secretoCifrado != "":
            usuarioA.markdown('## Usuario A')
            secretoRecibido = descifradoSecretoAsimetrica(secretoCifrado, usuarioA)
            if secretoRecibido is not None:
                iniciaChatLlave = cifradoLlaveSimetricaSalt(secretoRecibido)
                if iniciaChatLlave is not None:
                    usuarioA.button('Iniciar chat', on_click=actualizaAvance)

def iniciaChat():
    usuarioAMensajes, usuarioBMensajes = st.columns(2)
    usuarioBMensajes.markdown('## Usuario B')
    usuarioAMensajes.markdown('## Usuario A')

    usuarioAMensajes.text_input('Mensaje para usuario B:',)
    usuarioBMensajes.text_input('Mensaje para usuario A:',)

    # cifradoSinFirma(sinFirmaUsuarioA, sinFirmaUsuarioB, llaveSesion, llavePublicaUsuarioAPEM, llavePrivadaUsuarioBPEM, llavePublicaUsuarioBPEM, llavePrivadaUsuarioAPEM)
    # cifradoConFirma(conFirmaUsuarioA, conFirmaUsuarioB, llavePublicaUsuarioAPEM, llavePublicaUsuarioBPEM, llavePrivadaUsuarioAPEM, llavePrivadaUsuarioBPEM)

if __name__ == '__main__':
    if st.session_state.estado == False:
        compartirSecreto()
    if st.session_state.estado == True:
        iniciaChat()

# https://cryptobook.nakov.com/encryption-symmetric-and-asymmetric
# https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
# https://docs.streamlit.io/library/advanced-features/multipage-apps/custom-navigation

