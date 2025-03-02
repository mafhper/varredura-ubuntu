#!/bin/bash
#================================================================
# TÍTULO: Script Avançado de Configuração e Boas Práticas para Ubuntu
# DESCRIÇÃO: Instala pacotes essenciais, configura segurança e otimiza o sistema
# AUTOR: [Matheus :P Lima]
# VERSÃO: 3.0
# DATA: $(date +%d-%m-%Y)
#================================================================

# Arquivo de configuração - permite personalizar o script sem modificar o código
CONFIG_FILE="ubuntu_setup.conf"
DEFAULT_CONFIG="ubuntu_setup.conf.default"

# Funções de interface e utilitárias
#================================================================

# Definição de cores para melhor visualização
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para exibir cabeçalhos de seção
function print_section() {
    echo -e "\n${BOLD}${BLUE}===${NC} ${BOLD}$1${NC} ${BOLD}${BLUE}===${NC}\n"
}

# Função para exibir tarefas
function print_task() {
    echo -e "${YELLOW}➤ $1...${NC}"
}

# Função para verificar sucesso ou falha
function check_status() {
    local status=$?
    local ignore_error=${2:-0}
    
    if [ $status -eq 0 ]; then
        echo -e "  ${GREEN}✓ Concluído com sucesso${NC}"
        return 0
    else
        echo -e "  ${RED}✗ Falha na operação${NC}"
        
        # Se ignore_error for 1, apenas registrar falha sem perguntar
        if [ $ignore_error -eq 1 ]; then
            echo -e "  ${YELLOW}Continuando apesar do erro (modo não interativo)${NC}"
            return 1
        fi
        
        # Perguntar se deseja continuar mesmo com erro
        if [ $INTERACTIVE -eq 1 ]; then
            read -p "  Continuar mesmo com erro? (s/n): " choice
            if [[ "$choice" != "s" && "$choice" != "S" ]]; then
                echo -e "${RED}Script interrompido pelo usuário.${NC}"
                exit 1
            fi
        else
            # Em modo não interativo, continuar por padrão
            echo -e "  ${YELLOW}Continuando em modo não interativo...${NC}"
        fi
        return 1
    fi
}

# Função para criar backup do arquivo antes de modificá-lo
function backup_file() {
    if [ -f "$1" ]; then
        local backup_file="$1.bak.$(date +%Y%m%d%H%M%S)"
        cp "$1" "$backup_file"
        echo -e "  ${GREEN}✓ Backup criado: $backup_file${NC}"
        
        # Adicionar ao registro de backups
        echo "$backup_file" >> "$BACKUP_LOG"
    fi
}

# Verificar requisitos do sistema
function check_requirements() {
    print_task "Verificando requisitos do sistema"
    
    # Verificar se está sendo executado como root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Este script precisa ser executado como root (sudo).${NC}" 
        exit 1
    fi
    
    # Verificar o sistema operacional
    if ! command -v lsb_release &> /dev/null || ! lsb_release -i | grep -q -i "ubuntu"; then
        echo -e "${RED}Este script foi projetado para sistemas Ubuntu.${NC}"
        echo -e "${YELLOW}Sistema detectado: $(lsb_release -ds 2>/dev/null || echo "Desconhecido")${NC}"
        
        if [ $FORCE_EXECUTION -eq 1 ]; then
            echo -e "${YELLOW}Execução forçada ativada. Continuando mesmo em sistema não Ubuntu...${NC}"
        else
            exit 1
        fi
    fi
    
    check_status
}

# Criar arquivo de configuração padrão se não existir
function create_default_config() {
    if [ ! -f "$DEFAULT_CONFIG" ]; then
        print_task "Criando arquivo de configuração padrão"
        
        cat > "$DEFAULT_CONFIG" <<EOL
# Configuração padrão para o script de configuração Ubuntu
# Você pode copiar este arquivo para $CONFIG_FILE e personalizar as opções

# Modo de operação (0: interativo, 1: não interativo)
INTERACTIVE=1

# Forçar execução mesmo em sistemas não Ubuntu (0: não, 1: sim)
FORCE_EXECUTION=0

# Componentes a instalar (0: não, 1: sim)
INSTALL_BASIC_PKGS=1
INSTALL_SYSTEM_PKGS=1
INSTALL_SECURITY_PKGS=1
INSTALL_COMPRESSION_PKGS=1
INSTALL_MONITORING_PKGS=1
INSTALL_DOCKER=0
INSTALL_TIMESHIFT=1

# Configurações de segurança
SETUP_FIREWALL=1
SETUP_FAIL2BAN=1
SETUP_SSH=1
SETUP_RKHUNTER=1
SETUP_LYNIS=1
SETUP_APPARMOR=1

# Otimizações do sistema
SETUP_KERNEL_PARAMS=1
SETUP_RESOURCE_LIMITS=1
SETUP_DISK_SCHEDULER=1
SETUP_TLP=1

# Atualizações automáticas
SETUP_UNATTENDED_UPGRADES=1

# Tarefas de manutenção
SETUP_MAINTENANCE_TASKS=1

# Lista de pacotes personalizados (separe com espaços)
CUSTOM_PACKAGES=""

# Portas adicionais do firewall (separe com espaços: "80 443 8080")
ADDITIONAL_PORTS=""

# Opções de reinicialização
RESTART_SERVICES=1
REBOOT_AT_END=0
EOL
        check_status
    fi
}

# Carregar configurações
function load_config() {
    # Criar configuração padrão se não existir
    create_default_config
    
    # Carregar valores padrão
    source "$DEFAULT_CONFIG"
    
    # Sobrescrever com configurações personalizadas se existirem
    if [ -f "$CONFIG_FILE" ]; then
        print_task "Carregando configurações personalizadas"
        source "$CONFIG_FILE"
        check_status
    else
        print_task "Usando configurações padrão"
        cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
        check_status
    fi
}

# Atualizar o sistema
function update_system() {
    print_section "1. ATUALIZAÇÃO DO SISTEMA"

    print_task "Atualizando repositórios"
    apt update
    check_status
    
    print_task "Atualizando pacotes do sistema"
    apt upgrade -y
    check_status
    
    print_task "Atualizando distribuição (se houver nova versão)"
    apt dist-upgrade -y
    check_status
}

# Instalar pacotes essenciais
function install_essential_packages() {
    print_section "2. INSTALAÇÃO DE PACOTES ESSENCIAIS"
    
    # Pacotes divididos por categorias para melhor organização
    BASIC_PKGS="build-essential software-properties-common apt-transport-https ca-certificates curl wget git vim"
    SYSTEM_PKGS="htop net-tools unzip gnupg lsb-release iotop sysstat ntp"
    SECURITY_PKGS="ufw fail2ban rkhunter chkrootkit lynis auditd apparmor apparmor-utils"
    COMPRESSION_PKGS="p7zip-full p7zip-rar rar unrar zip unzip"
    MONITORING_PKGS="glances ncdu tlp powertop lm-sensors smartmontools"
    
    # Instalar pacotes conforme configuração
    if [ $INSTALL_BASIC_PKGS -eq 1 ]; then
        print_task "Instalando pacotes básicos"
        apt install -y $BASIC_PKGS
        check_status
    fi
    
    if [ $INSTALL_SYSTEM_PKGS -eq 1 ]; then
        print_task "Instalando pacotes de sistema"
        apt install -y $SYSTEM_PKGS
        check_status
    fi
    
    if [ $INSTALL_SECURITY_PKGS -eq 1 ]; then
        print_task "Instalando pacotes de segurança"
        apt install -y $SECURITY_PKGS
        check_status
    fi
    
    if [ $INSTALL_COMPRESSION_PKGS -eq 1 ]; then
        print_task "Instalando pacotes de compressão"
        apt install -y $COMPRESSION_PKGS
        check_status
    fi
    
    if [ $INSTALL_MONITORING_PKGS -eq 1 ]; then
        print_task "Instalando ferramentas de monitoramento"
        apt install -y $MONITORING_PKGS
        check_status
    fi
    
    # Instalar pacotes personalizados se especificados
    if [ ! -z "$CUSTOM_PACKAGES" ]; then
        print_task "Instalando pacotes personalizados"
        apt install -y $CUSTOM_PACKAGES
        check_status
    fi
    
    # Instalar Docker se habilitado
    if [ $INSTALL_DOCKER -eq 1 ]; then
        print_task "Instalando Docker"
        
        # Verificar se o Docker já está instalado
        if command -v docker &> /dev/null; then
            echo -e "  ${YELLOW}Docker já está instalado, pulando...${NC}"
        else
            curl -fsSL https://get.docker.com -o get-docker.sh
            sh get-docker.sh
            check_status
            
            print_task "Configurando Docker para iniciar no boot"
            systemctl enable docker
            systemctl start docker
            check_status
            
            print_task "Adicionando usuário atual ao grupo docker"
            # Obter o usuário que executou sudo (se aplicável)
            REAL_USER=$(logname 2>/dev/null || echo $SUDO_USER)
            if [ ! -z "$REAL_USER" ]; then
                usermod -aG docker $REAL_USER
                check_status
            else
                echo -e "  ${YELLOW}Não foi possível determinar o usuário real, pulando este passo${NC}"
            fi
        fi
    fi
}

# Configurar segurança
function setup_security() {
    print_section "3. CONFIGURAÇÃO DE SEGURANÇA"
    
    # Configurar firewall
    if [ $SETUP_FIREWALL -eq 1 ]; then
        print_task "Configurando firewall UFW"
        
        # Verificar se o UFW está instalado
        if ! command -v ufw &> /dev/null; then
            apt install -y ufw
        fi
        
        # Configuração básica
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        
        # Adicionar portas extras se especificadas
        if [ ! -z "$ADDITIONAL_PORTS" ]; then
            for port in $ADDITIONAL_PORTS; do
                ufw allow $port/tcp
                echo -e "  ${GREEN}✓ Adicionada porta $port/tcp${NC}"
            done
        else
            # Portas comuns se nenhuma personalizada for especificada
            ufw allow 80/tcp
            ufw allow 443/tcp
        fi
        
        # Ativar firewall apenas em modo interativo ou se forçado
        if [ $INTERACTIVE -eq 1 ]; then
            read -p "Deseja ativar o firewall UFW agora? (s/n): " enable_ufw
            if [[ "$enable_ufw" == "s" || "$enable_ufw" == "S" ]]; then
                echo "y" | ufw enable
                check_status
            fi
        elif [ $RESTART_SERVICES -eq 1 ]; then
            echo -e "  ${YELLOW}Ativando UFW em modo não interativo...${NC}"
            echo "y" | ufw enable
            check_status
        fi
    fi
    
    # Configurar Fail2ban
    if [ $SETUP_FAIL2BAN -eq 1 ]; then
        print_task "Configurando Fail2ban"
        
        # Verificar se o Fail2ban está instalado
        if ! command -v fail2ban-server &> /dev/null; then
            apt install -y fail2ban
        fi
        
        # Backup da configuração original
        backup_file "/etc/fail2ban/jail.conf"
        
        # Criar arquivo de configuração personalizado
        cat > /etc/fail2ban/jail.local <<EOL
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 6h
EOL
        
        if [ $RESTART_SERVICES -eq 1 ]; then
            systemctl enable fail2ban
            systemctl restart fail2ban
        else
            systemctl enable fail2ban
        fi
        check_status
    fi
    
    # Configurar SSH mais seguro
    if [ $SETUP_SSH -eq 1 ]; then
        print_task "Configurando SSH mais seguro"
        
        # Verificar se o SSH está instalado
        if ! command -v sshd &> /dev/null; then
            apt install -y openssh-server
        fi
        
        backup_file "/etc/ssh/sshd_config"
        
        # Ajustar configurações SSH para maior segurança
        sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        
        # Ajustar a autenticação por senha com opção para desativar
        if [ $INTERACTIVE -eq 1 ]; then
            read -p "Desativar autenticação por senha no SSH (requer configuração prévia de chaves SSH)? (s/n): " disable_pass
            if [[ "$disable_pass" == "s" || "$disable_pass" == "S" ]]; then
                sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
                sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
            fi
        fi
        
        # Outras configurações de segurança do SSH
        sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
        
        # Verificar se o banner já existe
        if ! grep -q "^Banner" /etc/ssh/sshd_config; then
            echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
        fi
        
        # Reiniciar SSH apenas em modo interativo ou se forçado
        if [ $INTERACTIVE -eq 1 ]; then
            read -p "Deseja reiniciar SSH para aplicar as configurações? (ATENÇÃO: Certifique-se de ter configurado acesso por chave) (s/n): " restart_ssh
            if [[ "$restart_ssh" == "s" || "$restart_ssh" == "S" ]]; then
                systemctl restart ssh
                check_status
            fi
        elif [ $RESTART_SERVICES -eq 1 ]; then
            echo -e "  ${YELLOW}Reiniciando SSH em modo não interativo...${NC}"
            systemctl restart ssh
            check_status
        fi
    fi
    
    # Configurar RKHunter
    if [ $SETUP_RKHUNTER -eq 1 ]; then
        print_task "Executando verificação inicial de rootkits"
        
        # Verificar se o RKHunter está instalado
        if ! command -v rkhunter &> /dev/null; then
            apt install -y rkhunter
        fi
        
        rkhunter --update
        rkhunter --propupd
        
        # Execução não interativa do rkhunter
        rkhunter --check --sk
        check_status
    fi
    
    # Executar Lynis
    if [ $SETUP_LYNIS -eq 1 ]; then
        print_task "Executando varredura com Lynis"
        
        # Verificar se o Lynis está instalado
        if ! command -v lynis &> /dev/null; then
            apt install -y lynis
        fi
        
        lynis audit system --quick
        check_status
    fi
    
    # Configurar AppArmor
    if [ $SETUP_APPARMOR -eq 1 ]; then
        print_task "Configurando AppArmor"
        
        # Verificar se o AppArmor está instalado
        if ! command -v apparmor_status &> /dev/null; then
            apt install -y apparmor apparmor-utils
        fi
        
        # Verificar status do AppArmor
        if systemctl is-active --quiet apparmor; then
            aa-enforce /etc/apparmor.d/*
            check_status
        else
            echo -e "  ${YELLOW}AppArmor não está ativo, tentando ativar...${NC}"
            systemctl enable apparmor
            systemctl start apparmor
            
            # Verificar novamente
            if systemctl is-active --quiet apparmor; then
                aa-enforce /etc/apparmor.d/*
                check_status
            else
                echo -e "  ${RED}Não foi possível ativar o AppArmor${NC}"
                check_status 1 $INTERACTIVE
            fi
        fi
    fi
}

# Aplicar otimizações do sistema
function optimize_system() {
    print_section "4. OTIMIZAÇÕES DO SISTEMA"
    
    # Ajustar parâmetros do kernel
    if [ $SETUP_KERNEL_PARAMS -eq 1 ]; then
        print_task "Ajustando parâmetros do kernel"
        backup_file "/etc/sysctl.conf"
        
        cat >> /etc/sysctl.conf <<EOL
# Melhorias de performance e segurança
# Reduzir uso de swap
vm.swappiness=10
# Melhorar cache do sistema de arquivos
vm.vfs_cache_pressure=50
# Aumentar limite de arquivos abertos
fs.file-max=100000
# Habilitar proteção contra execução em pilha
kernel.exec-shield=1
# Proteções de rede
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
# Proteção contra ataques ICMP
net.ipv4.icmp_echo_ignore_broadcasts=1
# Proteção contra IP spoofing
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
# Proteção contra ataques de tempo
net.ipv4.tcp_rfc1337=1
# Melhorar performance de rede
net.core.rmem_max=16777216
net.core.wmem_max=16777216
# Ignorar pings (opcional, descomente se desejar)
# net.ipv4.icmp_echo_ignore_all=1
EOL
        
        print_task "Aplicando configurações do kernel"
        sysctl -p
        check_status
    fi
    
    # Configurar limites de recursos
    if [ $SETUP_RESOURCE_LIMITS -eq 1 ]; then
        print_task "Configurando limites de recursos do sistema"
        backup_file "/etc/security/limits.conf"
        
        cat >> /etc/security/limits.conf <<EOL
# Aumentar limites de recursos para melhorar desempenho
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
* soft nproc 65535
* hard nproc 65535
* soft memlock unlimited
* hard memlock unlimited
EOL
        check_status
    fi
    
    # Otimizar o agendador de disco
    if [ $SETUP_DISK_SCHEDULER -eq 1 ]; then
        print_task "Otimizando o agendador de disco"
        
        # Verificar se há discos no sistema
        if [ -d "/sys/block" ]; then
            cat > /etc/udev/rules.d/60-scheduler.rules <<EOL
# Set deadline scheduler for non-rotating disks
ACTION=="add|change", KERNEL=="sd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="deadline"
# Set cfq scheduler for rotating disks
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="cfq"
EOL
            check_status
        else
            echo -e "  ${YELLOW}Nenhum disco detectado, pulando configuração do agendador${NC}"
        fi
    fi
    
    # Configurar TLP para otimizar bateria
    if [ $SETUP_TLP -eq 1 ]; then
        print_task "Configurando TLP para otimizar bateria (para laptops)"
        
        # Verificar se o TLP está instalado
        if ! command -v tlp &> /dev/null; then
            apt install -y tlp
        fi
        
        # Detectar se é laptop
        if [ -d "/sys/class/power_supply" ] && ls /sys/class/power_supply/BAT* 1> /dev/null 2>&1; then
            tlp start
            check_status
        else
            echo -e "  ${YELLOW}Sistema não parece ser um laptop, pulando TLP${NC}"
        fi
    fi
}

# Configurar atualizações automáticas
function setup_unattended_upgrades() {
    if [ $SETUP_UNATTENDED_UPGRADES -eq 1 ]; then
        print_section "5. CONFIGURAÇÃO DE ATUALIZAÇÕES AUTOMÁTICAS"
        
        print_task "Instalando e configurando atualizações automáticas"
        apt install -y unattended-upgrades apt-listchanges
        
        backup_file "/etc/apt/apt.conf.d/20auto-upgrades"
        cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOL
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOL
        
        backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOL
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}:\${distro_codename}-updates";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Mail "root";
EOL
        
        systemctl restart unattended-upgrades
        check_status
    fi
}

# Configurar backup
function setup_backup() {
    print_section "6. CONFIGURAÇÃO DE BACKUP"
    
    if [ $INSTALL_TIMESHIFT -eq 1 ]; then
        print_task "Instalando Timeshift para backups do sistema"
        
        # Verificar se o Timeshift já está instalado
        if ! command -v timeshift &> /dev/null; then
            add-apt-repository -y ppa:teejee2008/ppa
            apt update
            apt install -y timeshift
        else
            echo -e "  ${YELLOW}Timeshift já está instalado${NC}"
        fi
        check_status
    fi
    
    print_task "Configurando Rsync para backups de dados"
    if ! command -v rsync &> /dev/null; then
        apt install -y rsync
    else
        echo -e "  ${YELLOW}Rsync já está instalado${NC}"
    fi
    check_status
}

# Configurar tarefas de manutenção
function setup_maintenance_tasks() {
    if [ $SETUP_MAINTENANCE_TASKS -eq 1 ]; then
        print_section "7. TAREFAS DE MANUTENÇÃO AGENDADAS"
        
        print_task "Criando script de manutenção periódica"
        
        # Verificar se os diretórios existem
        if [ ! -d "/usr/local/bin" ]; then
            mkdir -p /usr/local/bin
        fi
        
        cat > /usr/local/bin/system_maintenance.sh <<'EOL'
#!/bin/bash
# Script de manutenção automática do sistema Ubuntu
# Versão: 1.1

# Configurar log
LOG_DIR="/var/log/maintenance"
mkdir -p $LOG_DIR
LOG_FILE="$LOG_DIR/system_maintenance_$(date +%Y%m%d).log"
MAIL_REPORT=0

# Função para exibir cabeçalhos de seção
function print_section() {
    echo "========== $1 =========="
}

# Iniciar log
exec > >(tee -a $LOG_FILE)
exec 2>&1

echo "========== Manutenção do Sistema - $(date) =========="

print_section "1. Verificando espaço em disco"
df -h | grep -v "tmpfs\|udev"

print_section "2. Atualizando o sistema"
apt update && apt upgrade -y

print_section "3. Limpando pacotes desnecessários"
apt autoremove -y && apt autoclean

print_section "4. Limpando caches"
rm -rf /home/*/.cache/thumbnails/* 2>/dev/null
journalctl --vacuum-time=7d

print_section "5. Verificando integridade do sistema"
echo "5.1. Verificando por rootkits..."
if command -v rkhunter &> /dev/null; then
    rkhunter --update
    rkhunter --check --skip-keypress
else
    echo "rkhunter não está instalado"
fi

print_section "6. Analisando recursos do sistema"
echo "6.1. Os 10 maiores arquivos/diretórios..."
find / -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -printf '%s %p\n' 2>/dev/null | sort -nr | head -10

echo "6.2. Processos que consomem mais recursos..."
ps aux --sort=-%mem | head -10

print_section "7. Verificando atualizações de segurança pendentes"
apt list --upgradable 2>/dev/null | grep -i security

print_section "8. Verificando saúde dos discos"
if command -v smartctl &> /dev/null; then
    for disk in $(lsblk -d -o name | grep -v NAME | grep -E '^sd|^nvme'); do
        echo "Verificando disco $disk:"
        smartctl -H /dev/$disk
    done
else
    echo "smartmontools não está instalado"
fi

print_section "9. Verificando logs do sistema para erros críticos"
grep -i 'error\|critical\|warning\|fail' /var/log/syslog | tail -20

print_section "10. Reiniciando serviços críticos"
if systemctl is-active --quiet fail2ban; then
    systemctl restart fail2ban
fi

if systemctl is-active --quiet ufw; then
    systemctl restart ufw
fi

print_section "11. Verificando tempo de atividade do sistema"
uptime

print_section "12. Verificando uso de memória"
free -h

# Enviar relatório por email (se configurado)
if [ $MAIL_REPORT -eq 1 ] && command -v mail &> /dev/null; then
    print_section "13. Enviando relatório por email"
    SUMMARY=$(grep -E "^==========" $LOG_FILE | tail -30)
    echo "$SUMMARY" | mail -s "Manutenção do Sistema $(hostname) - $(date +%Y-%m-%d)" root
fi

echo "========== Manutenção Concluída - $(date) =========="
EOL
        
        chmod +x /usr/local/bin/system_maintenance.sh
        check_status
        
        print_task "Configurando execução semanal da manutenção"
        
        # Verificar se o diretório existe
        if [ ! -d "/etc/cron.d" ]; then
            mkdir -p /etc/cron.d
        fi
        
        cat > /etc/cron.d/system_maintenance <<EOL
# Executar manutenção do sistema semanalmente (domingo às 3h da manhã)
0 3 * * 0 root /usr/local/bin/system_maintenance.sh
EOL
        check_status
    fi
}

# Limpeza final
function perform_cleanup() {
    print_section "8. LIMPEZA FINAL"
    
    print_task "Limpando pacotes órfãos e caches"
    apt autoremove -y
    apt autoclean
    check_status
    
    print_task "Limpando arquivos temporários"
    rm -rf /tmp/*
    check_status
}

# Personalização adicional
function customize_system() {
    print_section "9. PERSONALIZAÇÃO ADICIONAL"
    
    print_task "Criando aliases úteis para todos os usuários"
    
    # Verificar se o diretório existe
    if [ ! -d "/etc/profile.d" ]; then
        mkdir -p /etc/profile.d
    fi
    
    # Criar arquivo de aliases úteis
    cat > /etc/profile.d/00-aliases.sh <<'EOL'
#!/bin/bash
# Aliases úteis para todos os usuários

# Navegação
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# Proteção contra erros comuns
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

# Informações do sistema
alias meminfo='free -h'
alias cpuinfo='lscpu'
alias diskinfo='df -h'
alias netinfo='ip -c a'
alias sysinfo='uname -a && lsb_release -a'

# Comandos úteis
alias update='sudo apt update && sudo apt upgrade -y'
alias install='sudo apt install'
alias remove='sudo apt remove'
alias ports='netstat -tulanp'
alias services='systemctl list-units --type=service'
alias myip='curl -s ifconfig.me && echo'

# Editar arquivos de sistema comuns
alias ehost='sudo $EDITOR /etc/hosts'
alias efstab='sudo $EDITOR /etc/fstab'
alias essh='sudo $EDITOR /etc/ssh/sshd_config'
alias ealias='sudo $EDITOR /etc/profile.d/00-aliases.sh && source /etc/profile.d/00-aliases.sh'

# Serviços comuns
alias sshs='sudo systemctl status sshd'
alias sshstart='sudo systemctl start sshd'
alias sshrestart='sudo systemctl restart sshd'

# Log relacionados
alias syslog='sudo tail -f /var/log/syslog'
alias authlog='sudo tail -f /var/log/auth.log'
alias aptlog='sudo tail -f /var/log/apt/history.log'
EOL
    
    chmod +x /etc/profile.d/00-aliases.sh
    check_status
    
    print_task "Configurando prompt personalizado"
    cat > /etc/profile.d/01-prompt.sh <<'EOL'
#!/bin/bash
# Prompt personalizado para BASH

# Cores
RESET="\[\e[0m\]"
RED="\[\e[1;31m\]"
GREEN="\[\e[1;32m\]"
YELLOW="\[\e[1;33m\]"
BLUE="\[\e[1;34m\]"
MAGENTA="\[\e[1;35m\]"
CYAN="\[\e[1;36m\]"
WHITE="\[\e[1;37m\]"

# Definir o prompt personalizado
export PS1="${GREEN}\u@\h${RESET}:${BLUE}\w${RESET}\$ "

# Para root, usar prompt vermelho para evitar confusões
if [ $(id -u) -eq 0 ]; then
    export PS1="${RED}\u@\h${RESET}:${BLUE}\w${RESET}\$ "
fi
EOL
    
    chmod +x /etc/profile.d/01-prompt.sh
    check_status
    
    print_task "Configurando editores padrão"
    cat > /etc/profile.d/02-editor.sh <<'EOL'
#!/bin/bash
# Configurar editor padrão

# Detectar editor disponível (preferir vim, depois nano)
if command -v vim &> /dev/null; then
    export EDITOR=vim
    export VISUAL=vim
elif command -v nano &> /dev/null; then
    export EDITOR=nano
    export VISUAL=nano
fi
EOL
    
    chmod +x /etc/profile.d/02-editor.sh
    check_status
    
    print_task "Configurando mensagem de boas-vindas (MOTD)"
    backup_file "/etc/motd"
    
    cat > /etc/update-motd.d/99-custom-welcome <<'EOL'
#!/bin/bash
# Mensagem de boas-vindas personalizada
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
CPU=$(grep "model name" /proc/cpuinfo | head -n 1 | cut -d':' -f2 | sed 's/^ *//')
MEM=$(free -h | grep "Mem" | awk '{print $2}')
DISK=$(df -h --output=avail / | tail -n 1)
UPTIME=$(uptime -p)
USERS=$(who | wc -l)
LOAD=$(cat /proc/loadavg | awk '{print $1", "$2", "$3}')

echo "
+----------------------------------------------------+
|               SISTEMA UBUNTU SEGURO                |
+----------------------------------------------------+
  Hostname     : $HOSTNAME
  Kernel       : $KERNEL
  CPU          : $CPU
  Memória      : $MEM
  Disco livre  : $DISK
  Uptime       : $UPTIME
  Usuários     : $USERS usuário(s) conectado(s)
  Carga        : $LOAD
+----------------------------------------------------+
  O sistema foi configurado com o script avançado
  de configuração e boas práticas para Ubuntu.
+----------------------------------------------------+
"

# Verificar atualizações pendentes
if [ -f /var/lib/update-notifier/updates-available ]; then
  echo "$(cat /var/lib/update-notifier/updates-available)"
fi

# Mostrar incidentes de segurança (se existirem)
if [ -f /var/lib/update-notifier/hwe-eol ]; then
  /usr/lib/update-notifier/update-motd-hwe-eol
fi

# Verificar tarefas de manutenção pendentes
if [ -x /usr/lib/update-notifier/update-motd-reboot-required ]; then
  /usr/lib/update-notifier/update-motd-reboot-required
fi
EOL
    
    chmod +x /etc/update-motd.d/99-custom-welcome
    check_status
}

# Criar arquivo de relatório final
function generate_report() {
    print_section "10. GERANDO RELATÓRIO FINAL"
    
    print_task "Criando relatório de configuração do sistema"
    
    # Definir arquivo de relatório
    REPORT_FILE="/root/system_setup_report_$(date +%Y%m%d_%H%M%S).txt"
    
    # Cabeçalho do relatório
    cat > $REPORT_FILE <<EOL
===============================================
    RELATÓRIO DE CONFIGURAÇÃO DO SISTEMA
    Data: $(date)
    Hostname: $(hostname)
===============================================

SUMÁRIO DE CONFIGURAÇÕES APLICADAS:
EOL
    
    # Adicionar seções sobre o que foi configurado
    if [ $INSTALL_BASIC_PKGS -eq 1 ]; then
        echo "✓ Pacotes básicos instalados" >> $REPORT_FILE
    fi
    
    if [ $INSTALL_SYSTEM_PKGS -eq 1 ]; then
        echo "✓ Pacotes de sistema instalados" >> $REPORT_FILE
    fi
    
    if [ $INSTALL_SECURITY_PKGS -eq 1 ]; then
        echo "✓ Pacotes de segurança instalados" >> $REPORT_FILE
    fi
    
    if [ $SETUP_FIREWALL -eq 1 ]; then
        echo "✓ Firewall (UFW) configurado" >> $REPORT_FILE
        echo "  Status UFW:" >> $REPORT_FILE
        ufw status | sed 's/^/    /' >> $REPORT_FILE
    fi
    
    if [ $SETUP_FAIL2BAN -eq 1 ]; then
        echo "✓ Fail2ban configurado" >> $REPORT_FILE
        echo "  Status Fail2ban:" >> $REPORT_FILE
        if systemctl is-active --quiet fail2ban; then
            echo "    Ativo e em execução" >> $REPORT_FILE
        else
            echo "    Instalado mas não está em execução" >> $REPORT_FILE
        fi
    fi
    
    if [ $SETUP_SSH -eq 1 ]; then
        echo "✓ SSH configurado com maior segurança" >> $REPORT_FILE
    fi
    
    if [ $SETUP_KERNEL_PARAMS -eq 1 ]; then
        echo "✓ Parâmetros do kernel otimizados" >> $REPORT_FILE
    fi
    
    if [ $SETUP_UNATTENDED_UPGRADES -eq 1 ]; then
        echo "✓ Atualizações automáticas configuradas" >> $REPORT_FILE
    fi
    
    if [ $INSTALL_TIMESHIFT -eq 1 ]; then
        echo "✓ Timeshift instalado para backups" >> $REPORT_FILE
    fi
    
    if [ $SETUP_MAINTENANCE_TASKS -eq 1 ]; then
        echo "✓ Tarefas de manutenção automática configuradas" >> $REPORT_FILE
        echo "  Agendamento: Domingo às 3h da manhã" >> $REPORT_FILE
    fi
    
    # Adicionar informações do sistema
    echo -e "\nINFORMAÇÕES DO SISTEMA:" >> $REPORT_FILE
    echo "Sistema Operacional: $(lsb_release -ds)" >> $REPORT_FILE
    echo "Kernel: $(uname -r)" >> $REPORT_FILE
    echo "CPU: $(grep "model name" /proc/cpuinfo | head -n 1 | cut -d':' -f2 | sed 's/^ *//')" >> $REPORT_FILE
    echo "Memória Total: $(free -h | grep "Mem" | awk '{print $2}')" >> $REPORT_FILE
    echo "Espaço em Disco: " >> $REPORT_FILE
    df -h | grep -v "tmpfs" | sed 's/^/  /' >> $REPORT_FILE
    
    # Lista de backups criados
    if [ -f "$BACKUP_LOG" ]; then
        echo -e "\nBACKUPS CRIADOS:" >> $REPORT_FILE
        cat "$BACKUP_LOG" | sed 's/^/  /' >> $REPORT_FILE
    fi
    
    # Adicionar recomendações adicionais
    echo -e "\nPRÓXIMOS PASSOS RECOMENDADOS:" >> $REPORT_FILE
    echo "1. Executar verificação completa com rkhunter: sudo rkhunter --check" >> $REPORT_FILE
    echo "2. Criar seu primeiro backup com Timeshift: sudo timeshift --create" >> $REPORT_FILE
    echo "3. Revisar logs de segurança periodicamente: sudo tail -f /var/log/auth.log" >> $REPORT_FILE
    echo "4. Verificar status do firewall regularmente: sudo ufw status verbose" >> $REPORT_FILE
    echo "5. Configurar usuários e grupos adicionais conforme necessário" >> $REPORT_FILE
    
    # Final do relatório
    echo -e "\n===============================================" >> $REPORT_FILE
    echo "Relatório gerado pelo script de configuração automática v3.0" >> $REPORT_FILE
    echo "Data e hora: $(date)" >> $REPORT_FILE
    echo "===============================================" >> $REPORT_FILE
    
    echo -e "  ${GREEN}✓ Relatório gerado em: $REPORT_FILE${NC}"
}

# Função principal que coordena todas as outras
function main() {
    # Criar arquivos de log
    LOG_DIR="/var/log/ubuntu_setup"
    mkdir -p $LOG_DIR
    
    # Data/hora para nomes de arquivos
    DATETIME=$(date +%Y%m%d_%H%M%S)
    
    # Arquivos de log
    MAIN_LOG="$LOG_DIR/setup_$DATETIME.log"
    BACKUP_LOG="$LOG_DIR/backups_$DATETIME.log"
    
    # Iniciar registro de atividades
    echo "Iniciando script de configuração do Ubuntu em $(date)" > $MAIN_LOG
    echo "Lista de arquivos com backup:" > $BACKUP_LOG
    
    # Banner de boas-vindas
    clear
    echo -e "${BOLD}${GREEN}"
    echo "  ___   ___ _    _ ___  _   ___   ___  ___ ___  "
    echo " / __| / __| |  | | _ \| | | \ \ / / || __/ _ \ "
    echo " \__ \| (__| |__| |  _/| |_| |\ V /| || _| (_) |"
    echo " |___/ \___|____|_|_|  |___/  \_/ |_||___\___/ "
    echo -e "${NC}"
    echo -e "${BOLD}Script Avançado de Configuração e Boas Práticas para Ubuntu v3.0${NC}"
    echo -e "por ${BOLD}${BLUE}Matheus :P Lima${NC}"
    echo -e "\nData: $(date)\n"
    echo -e "Este script irá configurar seu sistema Ubuntu com boas práticas de segurança e desempenho."
    echo -e "Os logs completos serão salvos em ${YELLOW}$MAIN_LOG${NC}"
    echo -e "Os backups de arquivos originais serão registrados em ${YELLOW}$BACKUP_LOG${NC}\n"
    
    # Se for interativo, perguntar se deseja iniciar
    if [ $INTERACTIVE -eq 1 ]; then
        read -p "Deseja iniciar a configuração do sistema agora? (s/n): " start_setup
        if [[ "$start_setup" != "s" && "$start_setup" != "S" ]]; then
            echo -e "${RED}Script interrompido pelo usuário.${NC}"
            exit 0
        fi
    fi
    
    # Executar funções principais (com redirecionamento de log)
    {
        # Verificar requisitos antes de continuar
        check_requirements
        
        # Carregar configurações
        load_config
        
        # Executar funções na ordem correta
        update_system
        install_essential_packages
        setup_security
        optimize_system
        setup_unattended_upgrades
        setup_backup
        setup_maintenance_tasks
        customize_system
        perform_cleanup
        generate_report
        
        # Finalização
        print_section "11. FINALIZANDO"
        echo -e "\n${GREEN}${BOLD}Configuração concluída com sucesso!${NC}"
        echo -e "Um relatório detalhado foi gerado em ${YELLOW}/root/system_setup_report_*.txt${NC}"
        
        # Perguntar sobre reinicialização
        if [ $INTERACTIVE -eq 1 ]; then
            read -p "Deseja reiniciar o sistema agora para aplicar todas as configurações? (s/n): " reboot_now
            if [[ "$reboot_now" == "s" || "$reboot_now" == "S" ]]; then
                echo -e "${YELLOW}Reiniciando o sistema em 5 segundos...${NC}"
                sleep 5
                reboot
            else
                echo -e "${YELLOW}Lembre-se de reiniciar o sistema quando for conveniente.${NC}"
            fi
        elif [ $REBOOT_AT_END -eq 1 ]; then
            echo -e "${YELLOW}Configuração definida para reiniciar automaticamente.${NC}"
            echo -e "${YELLOW}Reiniciando o sistema em 10 segundos...${NC}"
            sleep 10
            reboot
        else
            echo -e "${YELLOW}Configuração concluída sem reinicialização.${NC}"
            echo -e "${YELLOW}Considere reiniciar para aplicar todas as mudanças.${NC}"
        fi
    } 2>&1 | tee -a $MAIN_LOG
}

# Execução principal com tratamento de CTRL+C
trap 'echo -e "\n${RED}Script interrompido pelo usuário.${NC}"; exit 1' INT

# Iniciar o script passando controle para função principal
main
