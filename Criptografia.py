from Verificador import calcula_chaves
from hashlib import sha256
import os

def xor_bytes(a:bytes, b:bytes)->bytes:
    return bytes(x^y for x,y in zip(a,b))

def hash_g(data: bytes) -> bytes:
    #Função G (expande o número aleatório).
    return sha256(data).digest()

def hash_h(data: bytes) -> bytes:
    #Função H (hash para mascarar o numero aleatorio).
    return sha256(data).digest()

def criptografia_OAEP(mensagem_bytes:bytes, n:int) -> bytes:
    # Random de 256 bits
    r = os.urandom(32)    

    # p1 = M xor G(r) 
    # Dividir em grupos de 32 bytes pra nao perder dados no XOR   
    chunks = []
    for i in range(0,len(mensagem_bytes),32):
        chunk = mensagem_bytes[i:i+32]
        aux_p1 = xor_bytes(chunk,hash_g(r))
        chunks.append(aux_p1)
    p1 = b"".join(chunks)

    # p2 = r xor H(p1)
    p2 = xor_bytes(r,hash_h(p1))

    # p1 || p2
    return p1 + p2 

def descriptografia_OAEP(mensagem_cifrada:bytes) -> bytes:
    p1 = mensagem_cifrada[:-32]
    p2 = mensagem_cifrada[-32:]

    # r = p2 xor H(p1)
    r = xor_bytes(p2, hash_h(p1))

    # M = p1 xor G(r)
    chunks = []
    for i in range(0,len(p1),32):
        chunk = p1[i:i+32]
        mensagem_aux = xor_bytes(chunk,hash_g(r))
        chunks.append(mensagem_aux)

    mensagem = b"".join(chunks)
    return mensagem

def divide_blocos(mensagem: str, n: int) -> list[bytes]:
    # Tamanho que cada bloco deve ter
    tamanho_bloco = int((n.bit_length() // 8) - 32 - 2)  

    mensagem_bytes = mensagem.encode('utf-8')
    blocos = []
    for i in range(0,len(mensagem_bytes),tamanho_bloco):
        bloco = mensagem_bytes[i:i+tamanho_bloco]
        bloco_oaep = criptografia_OAEP(bloco,n)
        blocos.append(bloco_oaep)
    return blocos

def criptografa_mensagem(mensagem: str, chave_publica: tuple) -> list[int]:
    n, e = chave_publica
    blocos = divide_blocos(mensagem, n)
    mensagem_criptografada = []
    
    for bloco in blocos: 
        m = int.from_bytes(bloco, byteorder='big')
        c = pow(m, e, n)
        mensagem_criptografada.append(c)
    return mensagem_criptografada

def descriptografa_mensagem(mensagem_criptografada: list, chave_privada: tuple) -> str:
    n, d = chave_privada
    mensagem_bytes = bytearray()
    for c in mensagem_criptografada:
        m = pow(c, d, n)
        bloco = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
        bloco_descriptografado = descriptografia_OAEP(bloco)

        mensagem_bytes.extend(bloco_descriptografado)
    
    return mensagem_bytes.decode('utf-8',errors='replace')

chave_publica, chave_privada = calcula_chaves()
mensagem = "O território que atualmente forma o Brasil foi oficialmente"

criptografia = criptografa_mensagem(mensagem, chave_publica)
print(f"Mensagem criptografada: {criptografia}")

descriptografado = descriptografa_mensagem(criptografia, chave_privada)
print(f"Mensagem descriptografada: {descriptografado}")