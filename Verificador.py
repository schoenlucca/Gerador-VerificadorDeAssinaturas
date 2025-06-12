# Parte 1 - Geração das e cifra

# Geração das chaves

import secrets

# Função responsável por gerar um número de 1024 bits, usada para gerar p e q
def gerador_de_1024_bits():
    bit_length = secrets.randbits(10) + 1024  # aleatório, mas pelo menos 1024 bits
    
    num = secrets.randbits(bit_length)
    num |= (1 << (bit_length - 1))
    num |= 1
    return num

import math

# Função para calcular o mdc entre dois valores
def mdc(a, b):
    while b:
        a, b = b, a % b
    return a

# Função usada para verificar se o valor é primo
def eh_primo(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(num)) + 1, 2):
        if num % i == 0:
            return False
    return True

def encontra_e(euler):
    # Tenta valores normalmente usados para e primeiro
    candidatos = [65537, 257, 17, 5, 3]
    for e in candidatos:
        if e < euler and gcd(e, euler) == 1:
            return e
    # Se nenhum dos valores padrão funcionar, faz busca sequencial por primos ímpares
    for e in range(3, euler, 2):
        if eh_primo(e) and mdc(e, euler) == 1:
            return e

# Função responsável por calcular o valor d
def calcula_chave(p,q):
    n = p * q
    euler = (p-1)*(q-1)
    e = encontra_e(euler)
    d = pow(e, -1, euler)
    return d





