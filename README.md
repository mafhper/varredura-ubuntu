# Script Avançado de Configuração e Boas Práticas para Ubuntu

## Descrição
Este script automatiza a configuração inicial de sistemas Ubuntu, aplicando boas práticas de segurança, desempenho e manutenção. Ele inclui:
- Instalação de pacotes essenciais
- Configuração de firewall e segurança
- Otimização do sistema
- Configuração de backups automáticos
- Aplicação de atualizações e manutenção preventiva

## Requisitos
- Ubuntu (versão recente recomendada)
- Permissões de superusuário (`sudo` ou `root`)

## Instalação e Uso
### 1. Baixar o script
```bash
wget https://raw.githubusercontent.com/seu-usuario/seu-repositorio/main/main3.sh
```

### 2. Torná-lo executável
```bash
chmod +x main3.sh
```

### 3. Executar o script
```bash
sudo ./main3.sh
```
O script pode ser executado de forma interativa ou automática, dependendo da configuração escolhida.

## Configuração
As opções de configuração estão no arquivo `ubuntu_setup.conf`. Se ele não existir, um modelo padrão será criado (`ubuntu_setup.conf.default`).

### Exemplo de opções configuráveis:
```ini
# Modo de operação (0: interativo, 1: não interativo)
INTERACTIVE=1

# Componentes a instalar (0: não, 1: sim)
INSTALL_BASIC_PKGS=1
INSTALL_SECURITY_PKGS=1
INSTALL_DOCKER=0

# Configurações de segurança
SETUP_FIREWALL=1
SETUP_FAIL2BAN=1
```

## Funcionalidades
- **Instalação de pacotes**: Pacotes essenciais, de segurança, compressão e monitoramento.
- **Configuração de segurança**: Firewall (UFW), Fail2Ban, RKHunter, SSH seguro, AppArmor.
- **Otimizações do sistema**: Ajustes no kernel, limites de recursos, agendador de disco.
- **Atualizações automáticas**: Configuração do `unattended-upgrades`.
- **Backups**: Instalação e configuração do Timeshift e Rsync.
- **Manutenção periódica**: Criação de cron jobs para limpeza e análise do sistema.
- **Personalizações**: Aliases úteis, prompt personalizado, mensagem de boas-vindas (MOTD).

## Logs e Relatórios
Os logs de execução e backups são armazenados em:
- `/var/log/ubuntu_setup/`
- `/root/system_setup_report_YYYYMMDD_HHMMSS.txt`

## Aviso
Este script faz modificações no sistema, incluindo instalação de pacotes, alteração de configurações de segurança e otimizações. Certifique-se de revisar o código antes de executar.

## Licença
Este projeto está disponível sob a licença MIT.

## Autor
Criado por **Matheus :P Lima**.

Contribuições e sugestões são bem-vindas!

