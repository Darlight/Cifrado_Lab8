"""
Universidad del Valle de Guatemala
Cifrado de Informacion
Seccion 11
Lic. Luis Alberto Suriano
Mario Perdomo   
Augusto Alonso
Andre Rodriguez
Josue Sagastume 
Christopher Barrios
Jose Ovado

signature_standard_PKCS.py
Proposito: Programa que simula un verificador de firmas digitales utilizando RSA y formas estandares de criptografia
"""
# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii


#Llave publica y privada de 1024 bits 
par_de_llaves = RSA.generate(bits=1024)
pubKey = par_de_llaves.publickey()

#Mensaje comun como firma , que utiliza el PKCS#1 v1.5 signature scheme (RSASP1)
texto = b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
hashing = SHA256.new(texto)
signer = PKCS115_SigScheme(par_de_llaves)
signature = signer.sign(hashing)
#La funcion de encriptacion toma la llave publica y un texto plano como argumentos
#Retorna una base de 64 bits codificado de string del cipher text 
print("Firma:", binascii.hexlify(signature))

#Verificacion aprovada de la firma digital
texto = b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
hashing = SHA256.new(texto)
verificacion = PKCS115_SigScheme(par_de_llaves.e)
try:
    verificacion.verify(hashing, signature)
    print("Firma es valida.")
except:
    print("Firma es invalida.")

#Verificacion denegada de la firma 
#La funcion de desencriptacion toma la llave privdada y el cipher text como argumentos
#Retorna el texto plano o mensaje
texto = b"Vegeta is a Simp with Bulma."
hashing = SHA256.new(texto)
verificacion = PKCS115_SigScheme(par_de_llaves.e)
try:
    verificacion.verify(hashing, signature)
    print("Firma es valida.")
    #Se valida con éxito posteriormente con la clave pública correspondiente.
except:
    #Si se manipula el mensaje o la firma o la clave pública, la firma no se valida.
    print("Firma es invalida.")


#El resultado del código anterior demuestra que la firma RSA PKCS # 1 con clave privada RSA de 1024 bits produce una firma digital de 1024 bits.


