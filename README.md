# 🔐 RSA com OAEP e Assinatura Digital - Projeto em Python

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Criptografia](https://img.shields.io/badge/Criptografia-RSA-green)
![Segurança](https://img.shields.io/badge/Segurança-OAEP-yellow)

Projeto que implementa um sistema completo de criptografia assimétrica usando RSA com OAEP e assinatura digital para verificação de integridade e autenticidade.

## ✨ Funcionalidades Principais

- **Geração de chaves RSA** com primos de 1024 bits usando o teste de Miller-Rabin
- **Criptografia/Descriptografia** com OAEP para proteção contra ataques
- **Assinatura digital** usando RSA com hash SHA3-256
- **Verificação de assinatura** para garantir autenticidade e integridade
- **Simulação completa** de troca de mensagens entre Alice (emissor) e Bob (receptor)

## 🔄 Fluxo de Funcionamento

### 📤 Processo de Envio
1. Mensagem é criptografada com a chave **pública do destinatário** (RSA+OAEP)
2. Mensagem é assinada com a chave **privada do remetente**
3. Pacote (mensagem criptografada + assinatura) é enviado

### 📥 Processo de Recebimento
1. Mensagem é descriptografada com a chave **privada do destinatário**
2. Assinatura é verificada com a chave **pública do remetente**
3. Se válida: mensagem é aceita | Se inválida: erro é reportado

## 🚀 Como Executar

1. **Pré-requisitos**:
   - Python 3.9 ou superior

2. **Clonar repositório**:
```bash
git clone https://github.com/schoenlucca/Gerador-VerificadorDeAssinaturas.git
python3 Criptografia.py

## Autores
- Carlos Caua
- Lucca Schoen 
