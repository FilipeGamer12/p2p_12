# p2p_12

Aplicativo de comunicação **ponto a ponto (P2P)** para trocar mensagens e arquivos diretamente entre dois computadores, sem depender de um servidor central de chat.

## Como utilizar

### 1. Instale as dependências

O projeto utiliza Python, PySide6/Qt WebEngine e `cryptography`.

```bash
pip install PySide6 PySide6-Essentials PySide6-Addons cryptography
```

> Dependendo da distribuição do Python e do sistema operacional, a instalação do PySide6 pode instalar os componentes auxiliares automaticamente. O aplicativo exige **PySide6 com Qt WebEngine**.

### 2. Execute o aplicativo

Na pasta do projeto:

```bash
python p2p_12.py
```

Também é possível iniciar usando um perfil específico:

```bash
python p2p_12.py --profile caminho/do/perfil
```

### 3. Compartilhe seu contato

Ao iniciar, o aplicativo cria ou carrega uma identidade local.

Na área **MINHA IDENTIDADE**, copie o campo **Meu contato** usando o botão **Copiar meu contato** e envie esse texto para a outra pessoa por qualquer meio externo.

A chave privada da identidade permanece no computador e não é incluída no contato compartilhado.

### 4. Adicione o outro usuário

No computador do outro usuário:

1. Cole o contato público recebido no campo **CONTATO**.
2. Clique em **Adicionar e conectar**.
3. Aguarde o status mudar para **ONLINE**.

Depois da conexão, as mensagens podem ser enviadas pelo campo de texto e pelo botão **Enviar**. Também é possível pressionar `Enter` para enviar uma mensagem.

### 5. Envie arquivos

Use **Enviar arquivo** para selecionar arquivos ou arraste-os para a área indicada abaixo da conversa.

Os arquivos recebidos são salvos na pasta de downloads configurada no aplicativo.

## Como o app funciona

O `p2p_12` combina uma interface gráfica feita com **Python + PySide6 + Qt WebEngine** com um backend local HTTP usado para conectar a interface ao núcleo P2P.

A comunicação entre os pares ocorre diretamente quando possível. O aplicativo suporta diferentes transportes:

- **TCP** — comunicação pela rede local ou por uma rede privada que forneça conectividade entre os dois computadores.
- **Tor** — comunicação pela Internet por meio de um endereço `.onion`.
- **Bluetooth** — descoberta e comunicação por dispositivos Bluetooth quando o suporte do sistema estiver disponível.
- **RadminVPN** — modo de TCP para redes privadas virtuais compatíveis.

O contato público contém a identidade e os endereços de transporte necessários para localizar o outro par. O formato atual usa o prefixo `P2P12.` e também mantém compatibilidade com contatos legados `RETROCHAT2.`.

### Identidade e autenticação

Cada instalação possui uma identidade criptográfica persistente baseada em **Ed25519**. O aplicativo exibe uma **fingerprint** derivada da chave pública para facilitar a conferência da identidade do contato.

Durante a conexão, os pares realizam um handshake autenticado e estabelecem uma chave de sessão usando **X25519 + HKDF**.

As mensagens e os dados transferidos pelo canal estabelecido são protegidos com **ChaCha20-Poly1305**.

A chave privada da identidade é armazenada localmente e não é enviada ao parceiro.

## Transportes

### TCP / rede local

É a opção mais simples quando os dois computadores conseguem se alcançar pela rede.

Em uma rede local, habilite **TCP (rede local)** em **Configurações**. O aplicativo abre uma porta TCP, normalmente a partir da porta `1212`, procurando uma porta livre caso necessário.

Se houver firewall, roteador ou outra política de rede bloqueando a comunicação, será necessário permitir o tráfego correspondente.

### Tor

O Tor permite estabelecer a comunicação sem exigir que os dois computadores estejam na mesma rede local.

Habilite **Tor (internet)** em **Configurações**. O aplicativo inicia o serviço Tor em segundo plano e incorpora o endereço `.onion` disponível ao contato público.

No Windows, o aplicativo pode baixar e preparar o **Tor Expert Bundle** oficial quando necessário.

### Bluetooth

O botão **Bluetooth** inicia uma busca por dispositivos Bluetooth disponíveis. O suporte efetivo depende do sistema operacional, dos adaptadores e das permissões disponíveis.

## Configurações

A janela **Configurações** permite alterar:

- nome de usuário exibido nas mensagens;
- pasta onde os arquivos recebidos serão salvos;
- transportes TCP, Tor e Bluetooth;
- modo TCP padrão ou RadminVPN;
- tema da interface.

As configurações são persistidas no perfil local.

## Janelas adicionais

O menu principal possui três janelas auxiliares:

- **Configurações** — altera as opções do aplicativo.
- **Sobre** — mostra informações básicas do projeto.
- **Debug** — exibe os logs do backend e do Tor para diagnóstico de problemas.

## Segurança e privacidade

O projeto foi desenvolvido para comunicação direta entre os pares:

- não há um servidor central de mensagens no fluxo normal;
- a identidade é mantida localmente;
- a chave privada não é compartilhada;
- a comunicação autenticada usa criptografia moderna;
- os arquivos recebidos são gravados localmente na pasta configurada.

O contato público **não deve ser tratado como segredo**, pois sua função é permitir que outro usuário encontre e autentique sua identidade. Já a chave privada deve permanecer protegida no computador.

## Limitações e observações

- A conectividade depende do transporte escolhido e da configuração da rede.
- TCP pode exigir regras de firewall ou uma rede com conectividade entre os pares.
- Tor precisa terminar sua inicialização antes que o endereço `.onion` esteja disponível.
- Bluetooth depende do suporte do sistema operacional e do hardware.
- O tamanho máximo de arquivo aceito pelo protocolo é de aproximadamente **512 MiB**.
- Para uma conexão segura, confira a fingerprint do contato por um canal confiável antes de trocar informações sensíveis.

## Estrutura do projeto

```text
p2p_12/
├── p2p_12.py
├── README.md
└── web/
    ├── index.html
    ├── settings.html
    ├── about.html
    └── debug.html
```

## Tecnologia

- Python
- PySide6
- Qt WebEngine
- cryptography
- TCP sockets
- Tor
- Bluetooth, quando disponível
