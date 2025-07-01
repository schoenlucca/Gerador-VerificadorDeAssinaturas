# Parte 1 - Geração das e cifra

# Geração das chaves

import secrets

# Função responsável por gerar um número de 1024 bits, usada para gerar p e q
def gerador_de_1024_bits_primo():
    while True:
        num = secrets.randbits(1024) | (1 << 1023) | 1  # Garante 1024 bits e ímpar
        if algoritmo_miller_rabin(num):
            return num

# Função para calcular o mdc entre dois valores
def mdc(a, b):
    while b:
        a, b = b, a % b
    return a

# Função usada para verificar se o valor é primo
def eh_primo(num):      #Aparentemente tem que ser mais eficiente
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0:
        return False

    max_divisor = num // 2 + 1
    #for i in range(3, int(math.sqrt(num)) + 1, 2):
    for i in range(3, max_divisor, 2):
        if num % i == 0:
            return False
    return True

import random

def algoritmo_miller_rabin(n,k=20):
    # n >= 5 e k = qntd de iteracoes
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
    # n -1 = (2**s) * d
    s,d = 0,n-1
    while d % 2 == 0:
        d //= 2
        s+=1

    for _ in range(k):
        a = random.randint(2,n-2)
        #x = a**d mod n
        x = pow(a,d,n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = pow(x,2,n)
            if x == n-1:
                break
        else:
            return False    # n é composto
    return True             # n provavelmente é primo


def encontra_e(euler):
    # Tenta valores normalmente usados para e primeiro
    candidatos = [65537, 257, 17, 5, 3]
    for e in candidatos:
        if e < euler and mdc(e, euler) == 1:
            return e
    # Se nenhum dos valores padrão funcionar, faz busca sequencial por primos ímpares
    for e in range(3, euler, 2):
        if eh_primo(e) and mdc(e, euler) == 1:
            return e

# Função responsável por calcular o valor d
def calcula_chaves():
    p = gerador_de_1024_bits_primo()
    q = gerador_de_1024_bits_primo()
    while p == q:
        q = gerador_de_1024_bits_primo()
    n = p * q
    euler = (p-1)*(q-1)
    e = encontra_e(euler)
    d = pow(e, -1, euler)
    return (n,e),(n,d)      # Retorna chave publica e chave privada





