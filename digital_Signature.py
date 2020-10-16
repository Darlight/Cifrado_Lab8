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

digital_Signature.py
Proposito: Programa que simula un verificador de firmas digitales utilizando RSA y formas estandares de criptografia
"""
# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii


#Llave publica y privada de 1024 bits 
llaves_Pares = RSA.generate(bits=1024)
llave_Publica = llaves_Pares.publickey()

"""
Numeros hexadecimales
Llave Publica:  (n=0xf51518d30754430e4b89f828fd4f1a8e8f44dd10e0635c0e93b7c01802729a37e1dfc8848d7fbbdf2599830268d544c1ecab4f2b19b6164a4ac29c8b1a4ec6930047397d0bb93aa77ed0c2f5d5c90ff3d458755b2367b46cc5c0d83f8f8673ec85b0575b9d1cea2c35a0b881a6d007d95c1cc94892bec61c2e9ed1599c1e605f, e=0x10001)
Llave Privada: (n=0xf51518d30754430e4b89f828fd4f1a8e8f44dd10e0635c0e93b7c01802729a37e1dfc8848d7fbbdf2599830268d544c1ecab4f2b19b6164a4ac29c8b1a4ec6930047397d0bb93aa77ed0c2f5d5c90ff3d458755b2367b46cc5c0d83f8f8673ec85b0575b9d1cea2c35a0b881a6d007d95c1cc94892bec61c2e9ed1599c1e605f, d=0x165ecc9b4689fc6ceb9c3658977686f8083fc2e5ed75644bb8540766a9a2884d1d82edac9bb5d312353e63e4ee68b913f264589f98833459a7a547e0b2900a33e71023c4dedb42875b2dfdf412881199a990dfb77c097ce71b9c8b8811480f1637b85900137231ab47a7e0cbecc0b011c2c341b6de2b2e9c24d455ccd1fc0c21)
"""

#Mensaje comun como firma , que utiliza el PKCS#1 v1.5 signature scheme (RSASP1)
texto = b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
hashing = SHA256.new(texto)

signer = PKCS115_SigScheme(llaves_Pares)
signature = signer.sign(hashing)
#La funcion de encriptacion toma la llave publica y un texto plano como argumentos
#Retorna una base de 64 bits codificado de string del cipher text 
print("Firma:", binascii.hexlify(signature))

#Verificacion aprovada de la firma digital
texto = b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
hashing = SHA256.new(texto)
verificacion = PKCS115_SigScheme(llave_Publica)
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
verificacion = PKCS115_SigScheme(llave_Publica)
try:
    verificacion.verify(hashing, signature)
    print("Firma es valida.")
    #Se valida con éxito posteriormente con la clave pública correspondiente.
except:
    #Si se manipula el mensaje o la firma o la clave pública, la firma no se valida.
    print("Firma es invalida.")


#El resultado del código anterior demuestra que la firma RSA PKCS # 1 con clave privada RSA de 1024 bits produce una firma digital de 1024 bits.


