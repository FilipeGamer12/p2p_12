# p2p_12

Cliente P2P privado e leve com interface web embutida em uma janela Qt sem moldura. O backend está implementado em `p2p_12.py` e provê descoberta de pares e transferência segura de arquivos.

**Como funciona (resumo técnico)**

- Identidade persistente: Ed25519 armazenada localmente.
- Troca de chaves: X25519 + Ed25519 para autenticação do handshake.
- Criptografia de sessão: HKDF-SHA256 para derivação de chaves e ChaCha20-Poly1305 para cifra e autenticação.
- Transporte: conexões TCP P2P; descoberta opcional por Bluetooth LE (Bleak).
- Transferência de arquivos: até 512 MB com verificação de integridade SHA-256.

## Quickstart (Windows)

- Executar via atalho: `launch_windows.bat`.
- Manual (venv):

```bat
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe p2p_12.py
```

Para perfis separados (identidades/estado isolados):

```bat
.venv\Scripts\python.exe p2p_12.py --profile alice
.venv\Scripts\python.exe p2p_12.py --profile bob
```

## Manual do Usuário

1. Preparação

   - Instale dependências em um ambiente virtual conforme o Quickstart.
   - No Windows, `launch_windows.bat` inicia a aplicação pronta.
   - Também há a opção de baixar p2p_12.exe.
2. Iniciando a aplicação

   - Ao executar, abre-se uma janela Qt sem moldura que carrega a interface web (HTML/CSS/JS).
3. Conexão com pares

   - A aplicação pode descobrir peers via Bluetooth LE (se adaptador disponível) ou conectar via TCP usando o endereço/ID do par.
   - Compartilhe seu identificador com o contato remoto para estabelecer a conexão.
4. Enviar e receber arquivos

   - Na interface web, seleccione o par de destino e escolha o arquivo para enviar.
   - O progresso da transferência é mostrado; a integridade é verificada por SHA-256 ao final.
   - Arquivos suportados até ~512 MB.
5. Perfis

   - Use o parâmetro `--profile <nome>` para executar instâncias com identidades/estado separados.
6. Segurança e privacidade

   - As chaves privadas são persistidas localmente; faça backup se necessário.
   - As comunicações usam handshake autenticado e cifragem autenticada de sessão.
7. Problemas comuns

   - Não aparece nenhum peer: verifique se o Bluetooth está ativado, ou se há bloqueio por firewall para conexões TCP.
   - Transferência falha: confirme espaço em disco e permissões na pasta de destino.

## Estrutura do projeto

```text
p2p_12/
├── p2p_12.py
├── web/
│   └── index.html
├── launch_windows.bat
├── requirements.txt
├── requirements-bluetooth.txt
└── android/
```
