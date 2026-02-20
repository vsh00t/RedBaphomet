#!/bin/bash
set -e

# Script de inicialización del Droplet para RedBaphomet
# Este script debe ejecutarse como root

echo "[+] Inicializando Droplet para RedBaphomet..."

# Crear usuario dedicado
echo "[+] Creando usuario redbaphomet..."
if ! id -u redbaphomet >/dev/null 2>&1; then
    useradd -m -s /bin/bash redbaphomet
    echo "redbaphomet:$(openssl rand -base64 16)" | chpasswd
fi

# Configurar sudo sin contraseña para el usuario
echo "[+] Configurando sudo para redbaphomet..."
echo "redbaphomet ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/redbaphomet
chmod 0440 /etc/sudoers.d/redbaphomet

# Instalar dependencias
echo "[+] Instalando dependencias..."
apt-get update
apt-get install -y \
    git \
    wget \
    curl \
    build-essential \
    zlib1g \
    zlib1g-dev \
    unzip \
    supervisor

# Crear directorios necesarios
echo "[+] Creando directorios..."
mkdir -p /home/redbaphomet/bin
mkdir -p /home/redbaphomet/scripts
mkdir -p /home/redbaphomet/logs
chown -R redbaphomet:redbaphomet /home/redbaphomet

# Clonar el repositorio (o usar el directorio ya clonado)
echo "[+] Configurando repositorio..."
if [ ! -d /home/redbaphomet/RedBaphomet ]; then
    sudo -u redbaphomet git clone https://github.com/vsh00t/RedBaphomet.git /home/redbaphomet/RedBaphomet
else
    sudo -u redbaphomet git -C /home/redbaphomet/RedBaphomet pull origin dev
fi

# Configurar firewall (abrir puerto del C2)
echo "[+] Configurando firewall..."
apt-get install -y ufw
ufw --force enable
ufw allow 22/tcp
ufw allow 31337/tcp  # Puerto del C2 (configurable)
ufw reload

echo "[+] Droplet inicializado correctamente!"
echo "[+] Usuario: redbaphomet"
echo "[+] Directorios creados: /home/redbaphomet/{bin,scripts,logs}"
