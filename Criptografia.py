from Verificador import calcula_chaves
import math

def divide_blocos(mensagem: str, n: int) -> list[bytes]:
    mensagem_bytes = mensagem.encode('utf-8')
    tamanho_bloco = int((n.bit_length() // 8) - 11)  # Espaço para padding
    blocos = [mensagem_bytes[i:i + tamanho_bloco] for i in range(0, len(mensagem_bytes), tamanho_bloco)]
    return blocos

def criptografa_mensagem(mensagem: str, chave_publica: tuple) -> list:
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
        num_bytes = (m.bit_length() + 7) // 8
        bloco = m.to_bytes(num_bytes, byteorder='big') 
        mensagem_bytes.extend(bloco)
    
    return mensagem_bytes.decode('utf-8')

# Exemplo de uso
chave_publica, chave_privada = calcula_chaves()
print(chave_publica)
print(chave_privada)
mensagem = "Brasil"

criptografia = criptografa_mensagem(mensagem, chave_publica)
print(f"Mensagem criptografada: {criptografia}")

descriptografado = descriptografa_mensagem(criptografia, chave_privada)
print(f"Mensagem descriptografada: {descriptografado}")