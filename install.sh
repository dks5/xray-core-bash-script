#!/bin/bash
# Используем строгий режим для большей надежности
set -euo pipefail

# --- Проверка на root-права ---
if [[ $EUID -ne 0 ]]; then
    echo "❌ Этот скрипт должен быть запущен с правами root."
    echo "Пожалуйста, используйте sudo."
    exit 1
fi

# --- УЛУЧШЕНИЕ: Автоопределение пакетного менеджера и установка зависимостей ---
echo "⚙️  Определяем пакетный менеджер и устанавливаем зависимости..."
PKG_CMD=""
if command -v apt-get &>/dev/null; then
    PKG_CMD="apt-get -y install"
    apt-get update
elif command -v dnf &>/dev/null; then
    PKG_CMD="dnf -y install"
elif command -v pacman &>/dev/null; then
    PKG_CMD="pacman -S --noconfirm"
else
    echo "❌ Не удалось определить пакетный менеджер (apt, dnf, pacman). Установите 'qrencode', 'curl', 'jq' вручную." >&2
    exit 1
fi
$PKG_CMD qrencode curl jq

# --- Включаем BBR ---
echo "🚀 Проверяем и включаем TCP BBR..."
if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    echo "✅ BBR включен."
else
    echo "✅ BBR уже включен."
fi

# --- Установка ядра Xray ---
# ВНИМАНИЕ: Мы доверяем скрипту установки с GitHub. Это стандартная практика, но несет в себе риски.
echo "📥 Загружаем и устанавливаем Xray-core..."
XRAY_INSTALL_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
XRAY_INSTALL_SCRIPT=$(mktemp)
# Скачиваем скрипт, а затем выполняем его. Это безопаснее, чем 'curl | bash'.
curl -4 -L -o "$XRAY_INSTALL_SCRIPT" "$XRAY_INSTALL_URL"
bash "$XRAY_INSTALL_SCRIPT" @ install
rm -f "$XRAY_INSTALL_SCRIPT"

# --- Генерация ключей и shortId для Reality ---
echo "🔑 Генерируем ключи для Reality..."
CONFIG_FILE="/usr/local/etc/xray/config.json"
KEYS_FILE="/usr/local/etc/xray/.keys.json" # ИЗМЕНЕНО: Используем JSON
mkdir -p "$(dirname "$KEYS_FILE")"

uuid=$(xray uuid)
keys_output=$(xray x25519)
private_key=$(echo "$keys_output" | awk -F': ' '/Private key/ {print $2}')
public_key=$(echo "$keys_output" | awk -F': ' '/Public key/ {print $2}')
short_id=$(openssl rand -hex 8)

# --- УЛУЧШЕНИЕ: Сохраняем ключи в надежном формате JSON ---
jq -n \
  --arg uuid "$uuid" \
  --arg pk "$private_key" \
  --arg pubk "$public_key" \
  --arg sid "$short_id" \
  '{uuid: $uuid, privateKey: $pk, publicKey: $pubk, shortId: $sid}' > "$KEYS_FILE"

# Устанавливаем безопасные права на файл с ключами
chmod 600 "$KEYS_FILE"

# --- Запрос данных у пользователя ---
echo ""
read -p "Введите домен для Reality (например, github.com): " server_name
server_name=${server_name:-"github.com"}

read -p "Введите порт для прослушивания [по умолчанию: 443]: " xray_port
xray_port=${xray_port:-443}

echo "✅ Используется домен: $server_name и порт: $xray_port"
echo ""

# --- Создаем файл конфигурации Xray ---
echo "📝 Создаем файл конфигурации Xray..."
cat << EOF > "$CONFIG_FILE"
{
    "log": {"loglevel": "warning"},
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"type": "field", "outboundTag": "block", "domain": ["geosite:category-ads-all"]},
            {"type": "field", "outboundTag": "block", "ip": ["geoip:cn"]}
        ]
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": $xray_port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "email": "main",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "$server_name:443",
                    "xver": 0,
                    "serverNames": ["$server_name"],
                    "privateKey": "$private_key",
                    "shortIds": ["$short_id"]
                }
            },
            "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}
        }
    ],
    "outbounds": [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"}
    ],
    "policy": {"levels": {"0": {"handshake": 3, "connIdle": 180}}}
}
EOF

# Устанавливаем безопасные права на файл конфигурации
chmod 600 "$CONFIG_FILE"

# --- Создаем исполняемые файлы для управления ---
echo "🛠️  Создаем скрипты для управления пользователями..."

# --- Утилита для получения IP ---
cat << 'EOF' > /usr/local/bin/get_public_ip
#!/bin/bash
set -eo pipefail
ip=$(curl -4 -s icanhazip.com || curl -4 -s ifconfig.me || curl -4 -s api.ipify.org)
if [[ -z "$ip" ]]; then echo "Ошибка: Не удалось получить публичный IP-адрес." >&2; exit 1; fi
echo "$ip"
EOF
chmod +x /usr/local/bin/get_public_ip


# --- userlist ---
cat << 'EOF' > /usr/local/bin/userlist
#!/bin/bash
set -euo pipefail
CONFIG_FILE="/usr/local/etc/xray/config.json"
get_vless_inbound_index() {
  jq 'map(.protocol == "vless") | index(true)' <<< "$(jq '.inbounds' "$CONFIG_FILE")"
}
vless_inbound_index=$(get_vless_inbound_index)
if [[ "$vless_inbound_index" == "null" ]]; then echo "VLESS inbound не найден." >&2; exit 1; fi
emails=($(jq -r ".inbounds[$vless_inbound_index].settings.clients[].email" "$CONFIG_FILE"))
if [[ ${#emails[@]} -eq 0 ]]; then echo "Список клиентов пуст."; exit 0; fi
echo "Список клиентов:"
for i in "${!emails[@]}"; do echo "$(($i+1)). ${emails[$i]}"; done
EOF
chmod +x /usr/local/bin/userlist


# --- newuser ---
cat << 'EOF' > /usr/local/bin/newuser
#!/bin/bash
set -euo pipefail
CONFIG_FILE="/usr/local/etc/xray/config.json"
LOCK_FILE="/var/lock/xray_config.lock"
get_vless_inbound_index() {
  jq 'map(.protocol == "vless") | index(true)' <<< "$(jq '.inbounds' "$CONFIG_FILE")"
}
(
    flock -x 200
    if ! command -v jq &>/dev/null; then echo "jq не установлен." >&2; exit 1; fi
    read -p "Введите имя пользователя (email): " email
    if [[ -z "$email" || "$email" == *" "* ]]; then echo "Имя не может быть пустым или содержать пробелы." >&2; exit 1; fi
    
    vless_inbound_index=$(get_vless_inbound_index)
    if [[ "$vless_inbound_index" == "null" ]]; then echo "VLESS inbound не найден." >&2; exit 1; fi
    
    if jq -e --arg email "$email" ".inbounds[$vless_inbound_index].settings.clients[] | select(.email == \$email)" "$CONFIG_FILE" > /dev/null; then
        echo "Пользователь '$email' уже существует." >&2; exit 1
    fi
    uuid=$(xray uuid)
    cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
    jq --arg email "$email" --arg uuid "$uuid" --argjson idx "$vless_inbound_index" \
       ".inbounds[\$idx].settings.clients += [{\"email\": \$email, \"id\": \$uuid, \"flow\": \"xtls-rprx-vision\"}]" \
       "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo "Пользователь '$email' добавлен. Перезапускаем Xray..."
    systemctl restart xray
    echo "Сервис перезапущен."
    sharelink "$email"
) 200>"$LOCK_FILE"
EOF
chmod +x /usr/local/bin/newuser


# --- rmuser (УЛУЧШЕННАЯ ВЕРСИЯ) ---
cat << 'EOF' > /usr/local/bin/rmuser
#!/bin/bash
set -euo pipefail
CONFIG_FILE="/usr/local/etc/xray/config.json"
LOCK_FILE="/var/lock/xray_config.lock"
get_vless_inbound_index() {
  jq 'map(.protocol == "vless") | index(true)' <<< "$(jq '.inbounds' "$CONFIG_FILE")"
}
(
    flock -x 200
    if ! command -v jq &>/dev/null; then echo "jq не установлен." >&2; exit 1; fi
    vless_inbound_index=$(get_vless_inbound_index)
    if [[ "$vless_inbound_index" == "null" ]]; then echo "VLESS inbound не найден." >&2; exit 1; fi
    
    # ИЗМЕНЕНО: Получаем список всех пользователей, КРОМЕ 'main'
    mapfile -t emails < <(jq -r ".inbounds[$vless_inbound_index].settings.clients[] | select(.email != \"main\") | .email" "$CONFIG_FILE")
    
    if [[ ${#emails[@]} -eq 0 ]]; then echo "Нет пользователей для удаления (кроме 'main')."; exit 0; fi
    echo "Выберите клиента для удаления:"
    for i in "${!emails[@]}"; do echo "$(($i+1)). ${emails[$i]}"; done
    read -p "Введите номер клиента: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#emails[@]} )); then
        echo "Ошибка: номер должен быть от 1 до ${#emails[@]}." >&2; exit 1
    fi
    selected_email="${emails[$((choice-1))]}"
    read -p "Вы уверены, что хотите удалить '$selected_email'? (y/n) " confirm
    if [[ "$confirm" != "y" ]]; then echo "Удаление отменено."; exit 0; fi
    cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
    jq --arg email "$selected_email" --argjson idx "$vless_inbound_index" \
       "(.inbounds[\$idx].settings.clients) |= map(select(.email != \$email))" \
       "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo "Клиент '$selected_email' удалён. Перезапускаем Xray..."
    systemctl restart xray
    echo "Сервис перезапущен."
) 200>"$LOCK_FILE"
EOF
chmod +x /usr/local/bin/rmuser


# --- sharelink (ОБНОВЛЕННАЯ ВЕРСИЯ С JSON) ---
cat << 'EOF' > /usr/local/bin/sharelink
#!/bin/bash
set -euo pipefail
CONFIG_FILE="/usr/local/etc/xray/config.json"
KEYS_FILE="/usr/local/etc/xray/.keys.json" # ИЗМЕНЕНО: читаем из JSON
get_vless_inbound_index() {
  jq 'map(.protocol == "vless") | index(true)' <<< "$(jq '.inbounds' "$CONFIG_FILE")"
}
generate_link() {
    local email=$1
    local vless_inbound_index=$2
    local uuid
    uuid=$(jq -r --arg email "$email" --argjson idx "$vless_inbound_index" \
        '.inbounds[$idx].settings.clients[] | select(.email == $email) | .id' "$CONFIG_FILE")
    if [[ -z "$uuid" ]]; then echo "Клиент '$email' не найден." >&2; return 1; fi

    local ip
    ip=$(get_public_ip)
    
    # УЛУЧШЕНИЕ: Читаем ключи из JSON-файла с помощью jq. Больше никакого awk!
    local publickey shortid port sni
    publickey=$(jq -r '.publicKey' "$KEYS_FILE")
    shortid=$(jq -r '.shortId' "$KEYS_FILE")
    port=$(jq -r ".inbounds[$vless_inbound_index].port" "$CONFIG_FILE")
    sni=$(jq -r ".inbounds[$vless_inbound_index].streamSettings.realitySettings.serverNames[0]" "$CONFIG_FILE")
    
    if [[ -z "$publickey" || -z "$shortid" || -z "$port" || -z "$sni" ]]; then
        echo "Ошибка: не удалось извлечь все параметры из файлов конфигурации." >&2; return 1;
    fi

    local link="vless://$uuid@$ip:$port?security=reality&sni=$sni&fp=chrome&pbk=$publickey&sid=$shortid&type=tcp&flow=xtls-rprx-vision&encryption=none#$email"
    echo -e "\n--- Ссылка для подключения '$email' ---\n$link\n\nQR-код:"
    qrencode -t ansiutf8 <<< "$link"
}
# --- Основная логика ---
vless_inbound_index=$(get_vless_inbound_index)
if [[ "$vless_inbound_index" == "null" ]]; then echo "VLESS inbound не найден." >&2; exit 1; fi
if [[ $# -gt 0 ]]; then
    generate_link "$1" "$vless_inbound_index"
    exit 0
fi
mapfile -t emails < <(jq -r ".inbounds[$vless_inbound_index].settings.clients[].email" "$CONFIG_FILE")
if [[ ${#emails[@]} -eq 0 ]]; then echo "Список клиентов пуст."; exit 0; fi
echo "Выберите клиента для генерации ссылки:"
for i in "${!emails[@]}"; do echo "$(($i+1)). ${emails[$i]}"; done
read -p "Введите номер клиента: " choice
if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#emails[@]} )); then
    echo "Ошибка: номер должен быть от 1 до ${#emails[@]}." >&2; exit 1
fi
generate_link "${emails[$((choice-1))]}" "$vless_inbound_index"
EOF
chmod +x /usr/local/bin/sharelink

# Создаем удобный симлинк для основного пользователя
ln -s /usr/local/bin/sharelink /usr/local/bin/mainuser

# --- НОВОЕ: Создаем скрипт для деинсталляции ---
TARGET_HOME=${SUDO_USER_HOME:-$HOME}
UNINSTALL_SCRIPT="$TARGET_HOME/uninstall_xray.sh"
echo "ℹ️  Создаем скрипт для удаления в $UNINSTALL_SCRIPT"
cat << EOF > "$UNINSTALL_SCRIPT"
#!/bin/bash
set -e
echo "Вы уверены, что хотите полностью удалить Xray и все его конфигурации?"
read -p "Введите 'yes' для подтверждения: " confirm
if [[ "\$confirm" != "yes" ]]; then
    echo "Удаление отменено."
    exit 0
fi

echo "Останавливаем и отключаем сервис Xray..."
systemctl stop xray
systemctl disable xray

echo "Удаляем управляющие скрипты..."
rm -f /usr/local/bin/{get_public_ip,userlist,newuser,rmuser,sharelink,mainuser}

echo "Удаляем файлы конфигурации и ключей..."
rm -rf /usr/local/etc/xray

echo "Удаляем лок-файл..."
rm -f /var/lock/xray_config.lock

echo "Запускаем официальный деинсталлятор Xray-core..."
# Команда для удаления самого ядра Xray
if [[ -f "/usr/local/bin/xray" ]]; then
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) @ remove --purge
fi

echo "Удаляем файл помощи и этот скрипт деинсталляции..."
rm -f "$TARGET_HOME/xray_help.txt"
rm -f "\$0"

echo "✅ Xray успешно удален из системы."
EOF
chmod +x "$UNINSTALL_SCRIPT"

# --- Завершение установки ---
systemctl restart xray
echo "✅ Xray-core успешно установлен и запущен."

HELP_FILE="$TARGET_HOME/xray_help.txt"
# ОБНОВЛЕНО: Добавлена информация про sudo и uninstall
cat << EOF > "$HELP_FILE"
🎉 Установка и настройка Xray завершена!

Команды для управления:
    mainuser          - Показать ссылку для основного пользователя ('main')
    newuser           - Создать нового пользователя
    rmuser            - Удалить пользователя
    userlist          - Показать список всех пользователей
    sharelink [email] - Показать ссылку для пользователя

Управление сервисом (требуется sudo):
    sudo systemctl restart xray
    sudo systemctl status xray
    sudo journalctl -u xray -f --no-pager

Основные файлы:
    Конфигурация: /usr/local/etc/xray/config.json
    Ключи Reality: /usr/local/etc/xray/.keys.json

Удаление:
    Для полного удаления Xray и всех компонентов запустите скрипт:
    bash $UNINSTALL_SCRIPT
EOF

echo ""
echo "📝 Подсказки по использованию сохранены в файле: $HELP_FILE"
echo "Вы можете просмотреть их командой: cat \"$HELP_FILE\""
echo ""
echo "--- 🔗 Ссылка для основного пользователя ('main') ---"
sharelink "main"
