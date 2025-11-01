#!/usr/bin/env bash
set -Eeuo pipefail

# === Интерактивный установщик базовой конфигурации Ubuntu ===
# Требования: root. Ввод данных через терминал. После каждого шага — очистка экрана.

# Глобальные переменные
readonly LOG_FILE="/var/log/autosettings.log"
readonly BACKUP_DIR="/root/autosettings_backup_$(date +%Y%m%d_%H%M%S)"
readonly SCRIPT_START_TIME=$(date +%s)

# Инициализация логирования и резервного копирования
init_logging() {
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "=== Запуск autosettings.sh $(date) ===" >> "$LOG_FILE"
  # Не перенаправляем stdout/stderr, чтобы не мешать whiptail и spinner
  # Логирование происходит через log_action
}

init_backup_dir() {
  mkdir -p "$BACKUP_DIR"
  echo "BACKUP_DIR=$BACKUP_DIR" > "$BACKUP_DIR/info.txt"
  echo "START_TIME=$(date)" >> "$BACKUP_DIR/info.txt"
}

log_action() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

check_internet() {
  if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && ! curl -fsS4 https://www.google.com >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

check_system_prerequisites() {
  log_action "Проверка системных требований"
  local issues=()
  
  # Проверка версии ОС
  if [[ ! -f /etc/os-release ]]; then
    issues+=("Не найдено /etc/os-release")
  else
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]] && [[ "$ID" != "debian" ]]; then
      issues+=("Скрипт предназначен для Ubuntu/Debian, обнаружено: $ID")
    fi
    log_action "ОС: $PRETTY_NAME"
  fi
  
  # Проверка места на диске (минимум 2GB свободно)
  local available_space
  available_space=$(df / | tail -1 | awk '{print $4}')
  if [[ $available_space -lt 2097152 ]]; then # 2GB в KB
    issues+=("Мало места на диске: менее 2GB свободно")
  fi
  log_action "Свободно на диске: $(( available_space / 1024 ))MB"
  
  # Проверка памяти
  local total_mem
  total_mem=$(free -m | awk '/^Mem:/{print $2}')
  log_action "Общая память: ${total_mem}MB"
  
  # Проверка архитектуры
  local arch
  arch=$(uname -m)
  log_action "Архитектура: $arch"
  
  if [[ ${#issues[@]} -gt 0 ]]; then
    echo
    print_header "⚠ ПРЕДУПРЕЖДЕНИЕ"
    echo "Обнаружены проблемы:"
    for issue in "${issues[@]}"; do
      echo "  • $issue"
    done
    echo
    if ! ask_yesno "Продолжить выполнение?" "n"; then
      log_action "Пользователь отменил выполнение из-за проблем с системой"
      exit 0
    fi
  fi
  
  return 0
}

require_root() { if [[ $EUID -ne 0 ]]; then echo "Запусти: sudo bash $0"; exit 1; fi; }

cls() { clear || true; }

# Простые функции для ввода данных в терминале
print_header() {
  echo "=========================================="
  echo "$1"
  echo "=========================================="
  echo
}

print_info() {
  echo "ℹ $1"
  echo
}

ask_yesno() {
  local prompt="$1"
  local default="${2:-n}"  # По умолчанию "нет"
  
  while true; do
    if [[ "$default" == "y" ]]; then
      echo -n "$prompt [Y/n]: "
    else
      echo -n "$prompt [y/N]: "
    fi
    read -r answer
    
    # Если пустой ответ - используем значение по умолчанию
    [[ -z "$answer" ]] && answer="$default"
    
    case "$answer" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo]) return 1 ;;
      *) echo "Пожалуйста, введите y или n" ;;
    esac
  done
}

ask_input() {
  local prompt="$1"
  local default="${2:-}"
  local var_name="${3:-}"
  
  if [[ -n "$default" ]]; then
    echo -n "$prompt [$default]: "
  else
    echo -n "$prompt: "
  fi
  
  read -r answer
  
  # Если пустой ответ и есть значение по умолчанию - используем его
  if [[ -z "$answer" ]] && [[ -n "$default" ]]; then
    answer="$default"
  fi
  
  if [[ -n "$var_name" ]]; then
    eval "$var_name=\"$answer\""
  else
    echo "$answer"
  fi
}

retry_on_error() {
  local step_name="$1"
  shift
  
  while true; do
    if "$@"; then
      return 0
    else
      local rc=$?
      echo
      echo "❌ Ошибка при выполнении: $step_name (код: $rc)"
      if ask_yesno "Повторить выполнение этого шага?" "y"; then
        echo
        continue
      else
        echo "Пропуск шага: $step_name"
        return $rc
      fi
    fi
  done
}
spinner() { # spinner "msg" cmd...
  local msg="$1"; shift; 
  log_action "Начало: $msg"
  echo -e "\n▶ $msg...\n"
  set +e; "$@" & local pid=$!; local spin='-\|/'; local i=0
  while kill -0 "$pid" 2>/dev/null; do 
    i=$(( (i+1)%4 )); 
    printf "\r[%c] Работаю..." "${spin:$i:1}"; 
    sleep 0.2
  done
  wait "$pid"; local rc=$?; set -e; printf "\r"
  if [[ $rc -eq 0 ]]; then
    echo "✓ Успешно завершено"
    log_action "Успешно: $msg"
  else
    echo "✗ Ошибка (код: $rc)"
    log_action "ОШИБКА (код $rc): $msg"
  fi
  echo
  return $rc
}
backup_file() { 
  local file="$1"
  if [[ -f "$file" ]] || [[ -d "$file" ]]; then
    local backup_path="$BACKUP_DIR${file}"
    mkdir -p "$(dirname "$backup_path")"
    cp -a "$file" "$backup_path" 2>/dev/null || true
    log_action "Резервная копия: $file -> $backup_path"
    # Также создаём локальную копию с timestamp для совместимости
    [[ -f "$file" ]] && cp -a "$file" "$file.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
  fi
}

validate_ssh_key() {
  local key="$1"
  # Проверяем формат ключа (ssh-ed25519, ssh-rsa, ecdsa-sha2, ssh-dss)
  if [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+|ssh-dss)\ +[A-Za-z0-9+/=]+ ]]; then
    return 0
  fi
  return 1
}

validate_time_format() {
  local time_str="$1"
  # Проверяем формат времени (например, 1h, 30m, 2d)
  if [[ "$time_str" =~ ^[0-9]+[smhd]$ ]]; then
    return 0
  fi
  return 1
}

validate_size_format() {
  local size="$1"
  # Проверяем формат размера (например, 500M, 1G)
  if [[ "$size" =~ ^[0-9]+[KMGT]?$ ]]; then
    return 0
  fi
  return 1
}

check_service_status() {
  local service="$1"
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    log_action "Сервис $service активен"
    return 0
  else
    log_action "ПРЕДУПРЕЖДЕНИЕ: сервис $service не активен"
    return 1
  fi
}

apply_and_restart_sshd_safely() {
  log_action "Проверка конфигурации SSH перед перезапуском"
  if sshd -t -f /etc/ssh/sshd_config; then
    systemctl restart ssh || systemctl restart sshd || true
    sleep 2
    check_service_status ssh || check_service_status sshd
  else
    log_action "ОШИБКА: Неверная конфигурация SSH, откат"
    echo "❌ Ошибка в /etc/ssh/sshd_config. Выполняется откат..."
    if compgen -G "/etc/ssh/sshd_config.bak.*" >/dev/null; then
      cp -f "$(ls -t /etc/ssh/sshd_config.bak.* | head -n1)" /etc/ssh/sshd_config
      log_action "Откат SSH конфигурации выполнен"
      echo "✓ Конфигурация SSH восстановлена из резервной копии"
    else
      echo "⚠ Резервная копия не найдена"
    fi
  fi
}

safe_remote_script() {
  local url="$1"
  local description="$2"
  local stdin_input="${3:-}"
  
  log_action "Загрузка и выполнение: $description ($url)"
  if ! check_internet; then
    log_action "ОШИБКА: Нет подключения к интернету для $description"
    echo "❌ Ошибка: Нет подключения к интернету. Пропуск: $description"
    return 1
  fi
  
  local script_content
  script_content=$(curl -fsS4 "$url" 2>&1)
  if [[ $? -ne 0 ]] || [[ -z "$script_content" ]]; then
    log_action "ОШИБКА: Не удалось загрузить скрипт $url"
    echo "❌ Ошибка: Не удалось загрузить скрипт: $description"
    echo "   URL: $url"
    return 1
  fi
  
  # Сохраняем скрипт во временный файл для логирования
  local tmp_script="/tmp/remote_script_$(date +%s).sh"
  echo "$script_content" > "$tmp_script"
  chmod +x "$tmp_script"
  log_action "Скрипт сохранён: $tmp_script"
  
  # Выполняем с обработкой ошибок и stdin при необходимости
  # Сохраняем вывод в лог, но также показываем пользователю
  local output_file="/tmp/remote_script_output_$(date +%s)"
  local rc=0
  if [[ -n "$stdin_input" ]]; then
    echo "$stdin_input" | bash "$tmp_script" > "$output_file" 2>&1 || rc=$?
  else
    bash "$tmp_script" > "$output_file" 2>&1 || rc=$?
  fi
  
  # Показываем вывод и сохраняем в лог
  cat "$output_file"
  cat "$output_file" >> "$LOG_FILE"
  rm -f "$output_file"
  rm -f "$tmp_script"
  
  if [[ $rc -ne 0 ]]; then
    log_action "ОШИБКА (код $rc): Выполнение скрипта $description"
  else
    log_action "Успешно: Выполнение скрипта $description"
  fi
  return $rc
}

# --- Шаг 1/10: Hostname + TZ ---
step_hostname_tz() {
  cls
  print_header "Шаг 1/13 — Имя сервера и часовой пояс"
  
  if ! ask_yesno "Установить hostname и часовой пояс?" "y"; then
    return 0
  fi
  
  ask_input "Введи hostname (например, prst-srv-01)" "" "new_hostname"
  [[ -z "$new_hostname" ]] && { echo "⚠ Пустое имя — пропуск."; return 0; }

  # Выбор часового пояса
  ask_input "Введи часовой пояс (например, Europe/Moscow, Europe/Kiev, Asia/Almaty)" "Europe/Moscow" "timezone"
  [[ -z "$timezone" ]] && timezone="Europe/Moscow"
  
  # Проверка валидности часового пояса
  if ! timedatectl list-timezones | grep -qxF "$timezone"; then
    echo "⚠ Неверный часовой пояс. Используется Europe/Moscow."
    timezone="Europe/Moscow"
  fi

  if retry_on_error "Установка hostname и часового пояса" spinner "Устанавливаю hostname и часовой пояс" bash -c "
    backup_file /etc/hostname
    backup_file /etc/hosts
    hostnamectl set-hostname \"$new_hostname\"
    grep -qE \"127.0.1.1\\s+$new_hostname\" /etc/hosts || echo -e \"127.0.1.1\t$new_hostname\" >> /etc/hosts
    timedatectl set-timezone \"$timezone\"
    timedatectl set-ntp true
  "; then
    echo "✓ Готово: Имя: $new_hostname, TZ: $timezone"
  fi
}

# --- Шаг 2/10: SSH порт/ключ/только ключи/root/лимиты ---
step_ssh_hardening() {
  cls
  print_header "Шаг 2/13 — Настройка SSH"
  echo "Настроить SSH: кастомный порт, вход только по ключам,"
  echo "root по ключам, MaxAuthTries=2, MaxSessions=2"
  echo
  
  if ! ask_yesno "Настроить SSH?" "y"; then
    return 0
  fi

  ask_input "Введи новый порт SSH (1024–65535)" "2222" "ssh_port"
  if ! [[ "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1024 || ssh_port > 65535 )); then
    echo "⚠ Некорректный порт. Пропуск."
    return 0
  fi

  echo "Вставь публичный SSH-ключ (ssh-ed25519/ssh-rsa...):"
  read -r pubkey
  [[ -z "$pubkey" ]] && { echo "⚠ Ключ не задан. Пропуск."; return 0; }
  if ! validate_ssh_key "$pubkey"; then
    echo "⚠ Неверный формат ключа. Ожидается: ssh-ed25519/ssh-rsa/ecdsa-sha2... Пропуск."
    log_action "ОШИБКА: Неверный формат SSH-ключа"
    return 0
  fi

  if retry_on_error "Настройка SSH" spinner "Применяю SSH-настройки" bash -c "
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
    grep -qxF \"$pubkey\" /root/.ssh/authorized_keys || echo \"$pubkey\" >> /root/.ssh/authorized_keys
    backup_file /etc/ssh/sshd_config
    sed -i \
      -e 's/^#\\?Port .*/Port $ssh_port/' \
      -e 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' \
      -e 's/^#\\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' \
      -e 's/^#\\?PubkeyAuthentication .*/PubkeyAuthentication yes/' \
      -e 's/^#\\?PermitRootLogin .*/PermitRootLogin prohibit-password/' \
      -e 's/^#\\?MaxAuthTries .*/MaxAuthTries 2/' \
      -e 's/^#\\?MaxSessions .*/MaxSessions 2/' \
      /etc/ssh/sshd_config || true
    grep -q '^Port ' /etc/ssh/sshd_config || echo 'Port $ssh_port' >> /etc/ssh/sshd_config
    grep -q '^PasswordAuthentication ' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
    grep -q '^ChallengeResponseAuthentication ' /etc/ssh/sshd_config || echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config
    grep -q '^PubkeyAuthentication ' /etc/ssh/sshd_config || echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
    grep -q '^PermitRootLogin ' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
    grep -q '^MaxAuthTries ' /etc/ssh/sshd_config || echo 'MaxAuthTries 2' >> /etc/ssh/sshd_config
    grep -q '^MaxSessions ' /etc/ssh/sshd_config || echo 'MaxSessions 2' >> /etc/ssh/sshd_config
  "; then
    apply_and_restart_sshd_safely
    echo "✓ Готово: Новый порт: $ssh_port, вход: только ключи; root — по ключу."
  fi
}

# --- Шаг 3/10: Создание sudo-пользователя ---
step_create_user() {
  cls
  print_header "Шаг 3/13 — Создание sudo-пользователя"
  
  if ! ask_yesno "Создать нового sudo-пользователя (рекомендуется для безопасности)?" "y"; then
    return 0
  fi
  
  ask_input "Введи имя пользователя" "" "username"
  [[ -z "$username" ]] && { echo "⚠ Пустое имя — пропуск."; return 0; }
  
  # Проверка на существование пользователя
  if id "$username" &>/dev/null; then
    echo "⚠ Пользователь $username уже существует. Пропуск."
    return 0
  fi
  
  echo "Вставь публичный SSH-ключ для пользователя (можно оставить пустым):"
  read -r pubkey_user
  
  if retry_on_error "Создание пользователя" spinner "Создаю пользователя $username" bash -c "
    useradd -m -s /bin/bash \"$username\"
    usermod -aG sudo \"$username\"
    echo \"$username ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/99-$username
    chmod 0440 /etc/sudoers.d/99-$username
  "; then
    if [[ -n "$pubkey_user" ]] && validate_ssh_key "$pubkey_user"; then
      if retry_on_error "Настройка SSH-ключа" spinner "Настраиваю SSH-ключ для $username" bash -c "
        mkdir -p /home/$username/.ssh
        chmod 700 /home/$username/.ssh
        echo \"$pubkey_user\" > /home/$username/.ssh/authorized_keys
        chmod 600 /home/$username/.ssh/authorized_keys
        chown -R $username:$username /home/$username/.ssh
      "; then
        echo "✓ Готово: Пользователь $username создан с sudo правами. SSH-ключ добавлен."
      fi
    else
      echo "✓ Готово: Пользователь $username создан с sudo правами. SSH-ключ не добавлен (неверный формат или пустой)."
    fi
    log_action "Создан пользователь: $username"
  fi
}

# --- Шаг 4/10: Обновление системы ---
step_updates_now() {
  cls
  print_header "Шаг 4/13 — Обновление системы"
  
  if ! ask_yesno "Выполнить apt update && apt -y full-upgrade?" "y"; then
    return 0
  fi
  
  if retry_on_error "Обновление системы" spinner "Обновляю систему" bash -c "apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade"; then
    echo "✓ Готово: Система обновлена."
  fi
}

# --- Шаг 5/10: Настройка swap ---
step_configure_swap() {
  cls
  print_header "Шаг 5/13 — Настройка swap"
  
  if ! ask_yesno "Настроить swap-файл (рекомендуется если swap отсутствует)?" "y"; then
    return 0
  fi
  
  # Проверяем существующий swap
  local swap_total
  swap_total=$(free -m | awk '/^Swap:/{print $2}')
  
  if [[ $swap_total -gt 0 ]]; then
    echo "⚠ Обнаружен существующий swap (${swap_total}MB)"
    if ! ask_yesno "Продолжить настройку?" "n"; then
      return 0
    fi
  fi
  
  ask_input "Размер swap в MB (рекомендуется: размер RAM или 2048)" "2048" "swap_size_mb"
  if ! [[ "$swap_size_mb" =~ ^[0-9]+$ ]] || (( swap_size_mb < 256 || swap_size_mb > 16384 )); then
    echo "⚠ Неверный размер (256-16384 MB). Используется 2048MB."
    swap_size_mb=2048
  fi
  
  if retry_on_error "Настройка swap" spinner "Настраиваю swap-файл ${swap_size_mb}MB" bash -c "
    # Отключаем существующий swap если есть
    swapoff -a 2>/dev/null || true
    
    # Удаляем старый swap-файл если есть
    [[ -f /swapfile ]] && rm -f /swapfile
    
    # Создаём новый swap-файл
    dd if=/dev/zero of=/swapfile bs=1M count=$swap_size_mb status=progress
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Добавляем в fstab если ещё нет
    if ! grep -q '/swapfile' /etc/fstab; then
      backup_file /etc/fstab
      echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    # Настраиваем swappiness (оптимально 10 для серверов)
    backup_file /etc/sysctl.conf
    if ! grep -q '^vm.swappiness=' /etc/sysctl.conf; then
      echo 'vm.swappiness=10' >> /etc/sysctl.conf
      sysctl vm.swappiness=10
    fi
  "; then
    local new_swap
    new_swap=$(free -m | awk '/^Swap:/{print $2}')
    echo "✓ Готово: Swap настроен: ${new_swap}MB, Swappiness: 10"
    log_action "Настроен swap: ${swap_size_mb}MB"
  fi
}

# --- Шаг 6/10: Базовые компоненты + Docker/compose ---
step_components() {
  cls
  print_header "Шаг 6/13 — Базовые компоненты и Docker"
  
  if ! ask_yesno "Установить базовые утилиты и Docker + compose-plugin?" "y"; then
    return 0
  fi

  if retry_on_error "Установка базовых пакетов" spinner "Ставлю базовые пакеты" bash -c "
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ca-certificates curl gnupg lsb-release git htop wget unzip jq \
      software-properties-common apt-transport-https
  "; then
    if retry_on_error "Установка Docker" spinner "Устанавливаю Docker" bash -c "
      curl -fsSL https://get.docker.com | sh
      systemctl enable --now docker
    "; then
      spinner "Устанавливаю docker compose plugin" bash -c "
        DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin || true
      "
      echo "✓ Готово: Базовые утилиты и Docker установлены."
    fi
  fi
}

# --- Шаг 7/10: Fail2Ban (базовая защита SSH) ---
step_fail2ban_basic() {
  cls
  print_header "Шаг 7/13 — Fail2Ban"
  
  if ! ask_yesno "Установить и включить базовую защиту SSH через fail2ban?" "y"; then
    return 0
  fi

  # Определяем порт SSH из конфигурации
  local ssh_port
  ssh_port=$(awk '/^Port[[:space:]]+/ {print $2}' /etc/ssh/sshd_config | tail -n1)
  [[ -z "$ssh_port" ]] && ssh_port=22

  # Считаем текущий публичный IP (для whitelist), если получится
  local pub_ip=""
  pub_ip=$(curl -fsS4 https://api.ipify.org || curl -fsS4 https://ifconfig.me || true)
  local ignoreip_default="${pub_ip}"

  echo "Автодетект IP: ${ignoreip_default:-нет}"
  ask_input "Whitelist (ignoreip) - адреса/сети через пробел (доверенные IP), можно оставить пустым" "$ignoreip_default" "ignoreip"
  ask_input "Время бана (напр., 1h, 12h, 1d)" "1h" "bantime"
  if ! validate_time_format "$bantime"; then
    echo "⚠ Неверный формат времени бана. Используется значение по умолчанию: 1h"
    bantime="1h"
  fi
  ask_input "Окно анализа попыток (напр., 10m, 15m)" "10m" "findtime"
  if ! validate_time_format "$findtime"; then
    echo "⚠ Неверный формат времени окна. Используется значение по умолчанию: 10m"
    findtime="10m"
  fi
  ask_input "Допустимо неудачных попыток до бана" "3" "maxretry"
  if ! [[ "$maxretry" =~ ^[0-9]+$ ]] || (( maxretry < 1 || maxretry > 10 )); then
    echo "⚠ Неверное значение maxretry (1-10). Используется значение по умолчанию: 3"
    maxretry="3"
  fi

  if retry_on_error "Установка fail2ban" spinner "Устанавливаю и настраиваю fail2ban" bash -c "
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
    systemctl enable --now fail2ban

    backup_file /etc/fail2ban/jail.local

    cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 ${ignoreip}
bantime  = ${bantime}
findtime = ${findtime}
maxretry = ${maxretry}
backend  = systemd

[sshd]
enabled  = true
port     = ${ssh_port}
filter   = sshd
# backend=systemd позволяет читать journal без пути к logpath
EOF

    systemctl restart fail2ban
  "; then
    sleep 2
    check_service_status fail2ban
    local jail_status; jail_status=$(fail2ban-client status sshd 2>/dev/null || echo "Тюрьма sshd ещё не активна")
    echo "✓ Готово: Fail2Ban установлено и включено."
    echo "  Порт SSH: ${ssh_port}"
    echo "  Статус: ${jail_status}"
  fi
}

# --- Шаг 8/10: Автообновления (robust) ---
step_unattended() {
  cls
  print_header "Шаг 8/13 — Автообновления"
  
  if ! ask_yesno "Включить unattended-upgrades (безопасность + обычные обновления)?" "y"; then
    return 0
  fi

  if retry_on_error "Настройка автообновлений" spinner "Настраиваю unattended-upgrades и таймеры" bash -c '
    set -e

    # 1) Пакет
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades

    # 2) Периодика APT — создаём 20auto-upgrades с нужными ключами
    cat >/etc/apt/apt.conf.d/20auto-upgrades <<'"'"'CFG'"'"'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CFG

    # 3) Политика: ставим security + updates (не только security)
    . /etc/os-release || true
    CODENAME="${VERSION_CODENAME:-$(lsb_release -sc 2>/dev/null || echo stable)}"

    cat >/etc/apt/apt.conf.d/51unattended-upgrades <<EOF
Unattended-Upgrade::Origins-Pattern {
        "origin=Ubuntu,archive=\${distro_codename}-security";
        "origin=Ubuntu,archive=\${distro_codename}-updates";
};
// очищать зависимости, но не перезагружать автоматически
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    # 4) Размаскируем и включим таймеры APT
    systemctl unmask apt-daily.service apt-daily.timer apt-daily-upgrade.service apt-daily-upgrade.timer || true
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

    # 5) Перезапустим таймеры (на всякий)
    systemctl restart apt-daily.timer apt-daily-upgrade.timer

    # 6) Немедленно обновим индексы, чтобы всё поехало
    apt-get update -y
  '; then
    local t1 t2
    t1=$(systemctl is-enabled apt-daily.timer 2>/dev/null || true)
    t2=$(systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null || true)
    echo "✓ Готово: unattended-upgrades включён."
    echo "  apt-daily.timer: ${t1}"
    echo "  apt-daily-upgrade.timer: ${t2}"
  fi
}

# --- Шаг 9/10: journald (лимиты + 4 месяца) ---
step_journald_limits() {
  cls
  print_header "Шаг 9/13 — Логи journald"
  
  if ! ask_yesno "Ограничить размер журналов и хранить не более 4 месяцев?" "y"; then
    return 0
  fi
  
  ask_input "Лимит journald SystemMaxUse (например, 500M или 1G)" "500M" "max_use"
  if ! validate_size_format "$max_use"; then
    echo "⚠ Неверный формат размера. Используется значение по умолчанию: 500M"
    max_use="500M"
  fi

  if retry_on_error "Настройка journald" spinner "Настраиваю journald" bash -c "
    backup_file /etc/systemd/journald.conf
    awk '
      BEGIN{f1=0;f2=0}
      /^#?SystemMaxUse=/ {print \"SystemMaxUse=$max_use\"; f1=1; next}
      /^#?SystemMaxFileSize=/ {print \"SystemMaxFileSize=50M\"; f2=1; next}
      {print}
      END{
        if(f1==0) print \"SystemMaxUse=$max_use\";
        if(f2==0) print \"SystemMaxFileSize=50M\";
      }
    ' /etc/systemd/journald.conf > /etc/systemd/journald.conf.new
    mv /etc/systemd/journald.conf.new /etc/systemd/journald.conf
    systemctl restart systemd-journald
    echo 'PATH=/usr/sbin:/usr/bin:/sbin:/bin
0 3 * * 0 root /usr/bin/journalctl --vacuum-time=120d >/dev/null 2>&1' > /etc/cron.d/journald_vacuum_120d
  "; then
    echo "✓ Готово: Лимит: $max_use; хранение: 120 дней."
  fi
}

# --- Шаг 10/10: Кастомный MOTD (автоответ y) ---
step_motd_custom() {
  cls
  print_header "Шаг 10/13 — Кастомный MOTD"
  
  if ! ask_yesno "Отключить стандартный MOTD и поставить кастомный?" "y"; then
    return 0
  fi

  spinner "Отключаю стандартный MOTD" bash -c "
    if [[ -d /etc/update-motd.d ]]; then
      backup_file /etc/update-motd.d
      chmod -x /etc/update-motd.d/* || true
    fi
    : > /etc/motd
  "
  if safe_remote_script "https://dignezzz.github.io/server/dashboard.sh" "Кастомный MOTD" "yes"; then
    echo "✓ Готово: Кастомный MOTD установлен."
  else
    echo "❌ Ошибка: Не удалось установить кастомный MOTD. Проверьте логи: $LOG_FILE"
  fi
}

# --- Шаг 11/10: sysctl_opt.sh и unlimit_server.sh ---
step_sysctl_unlimit() {
  cls
  print_header "Шаг 11/13 — Оптимизации системы"
  
  if ! ask_yesno "Запустить sysctl_opt.sh и unlimit_server.sh (рекомендуется)?" "y"; then
    return 0
  fi
  
  local success_count=0
  if safe_remote_script "https://dignezzz.github.io/server/sysctl_opt.sh" "sysctl оптимизации"; then
    ((success_count++))
  fi
  if safe_remote_script "https://dignezzz.github.io/server/unlimit_server.sh" "unlimit оптимизации"; then
    ((success_count++))
  fi
  
  if [[ $success_count -eq 2 ]]; then
    echo "✓ Готово: Все оптимизации применены успешно."
  elif [[ $success_count -eq 1 ]]; then
    echo "⚠ Частично: Применена только часть оптимизаций. Проверьте логи: $LOG_FILE"
  else
    echo "❌ Ошибка: Не удалось применить оптимизации. Проверьте логи: $LOG_FILE"
  fi
}

# --- Шаг 12/10: Дополнительные SSH настройки безопасности ---
step_ssh_additional_hardening() {
  cls
  print_header "Шаг 12/13 — Дополнительные SSH настройки"
  
  if ! ask_yesno "Применить дополнительные настройки безопасности SSH?" "y"; then
    return 0
  fi
  
  if retry_on_error "Дополнительные SSH настройки" spinner "Применяю дополнительные SSH настройки" bash -c "
    backup_file /etc/ssh/sshd_config
    
    # Отключаем X11 forwarding
    sed -i 's/^#\\?X11Forwarding .*/X11Forwarding no/' /etc/ssh/sshd_config
    grep -q '^X11Forwarding ' /etc/ssh/sshd_config || echo 'X11Forwarding no' >> /etc/ssh/sshd_config
    
    # Отключаем UseDNS для ускорения подключения
    sed -i 's/^#\\?UseDNS .*/UseDNS no/' /etc/ssh/sshd_config
    grep -q '^UseDNS ' /etc/ssh/sshd_config || echo 'UseDNS no' >> /etc/ssh/sshd_config
    
    # Включаем TCPKeepAlive
    sed -i 's/^#\\?TCPKeepAlive .*/TCPKeepAlive yes/' /etc/ssh/sshd_config
    grep -q '^TCPKeepAlive ' /etc/ssh/sshd_config || echo 'TCPKeepAlive yes' >> /etc/ssh/sshd_config
    
    # Отключаем PermitEmptyPasswords
    sed -i 's/^#\\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    grep -q '^PermitEmptyPasswords ' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
    
    # Устанавливаем ClientAliveInterval и ClientAliveCountMax
    sed -i 's/^#\\?ClientAliveInterval .*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    grep -q '^ClientAliveInterval ' /etc/ssh/sshd_config || echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config
    
    sed -i 's/^#\\?ClientAliveCountMax .*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    grep -q '^ClientAliveCountMax ' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 2' >> /etc/ssh/sshd_config
  "; then
    apply_and_restart_sshd_safely
    echo "✓ Готово: Дополнительные SSH настройки применены:"
    echo "  - X11Forwarding: no"
    echo "  - UseDNS: no"
    echo "  - TCPKeepAlive: yes"
    echo "  - ClientAliveInterval: 300"
    log_action "Применены дополнительные SSH настройки безопасности"
  fi
}

# --- Функция проверки целостности системы ---
check_system_integrity() {
  log_action "Проверка целостности системы после установки"
  local issues=()
  local warnings=()
  
  # Проверка критических сервисов
  local critical_services=("ssh" "sshd" "docker" "fail2ban")
  for service in "${critical_services[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}"; then
      if ! systemctl is-active --quiet "$service" 2>/dev/null; then
        issues+=("Сервис $service не активен")
      fi
    fi
  done
  
  # Проверка SSH конфигурации
  if ! sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
    issues+=("Ошибка в конфигурации SSH")
  fi
  
  # Проверка swap
  local swap_total
  swap_total=$(free -m | awk '/^Swap:/{print $2}')
  if [[ $swap_total -eq 0 ]]; then
    warnings+=("Swap не настроен (может быть нормально)")
  fi
  
  # Проверка места на диске после установки
  local available_space
  available_space=$(df / | tail -1 | awk '{print $4}')
  if [[ $available_space -lt 1048576 ]]; then # 1GB в KB
    warnings+=("Мало места на диске: менее 1GB свободно")
  fi
  
  # Формируем отчёт
  local report="Проверка завершена.\n\n"
  if [[ ${#issues[@]} -eq 0 ]] && [[ ${#warnings[@]} -eq 0 ]]; then
    report+="✓ Все проверки пройдены успешно."
  else
    if [[ ${#issues[@]} -gt 0 ]]; then
      report+="ОШИБКИ:\n"
      for issue in "${issues[@]}"; do
        report+="✗ $issue\n"
      done
      report+="\n"
    fi
    if [[ ${#warnings[@]} -gt 0 ]]; then
      report+="ПРЕДУПРЕЖДЕНИЯ:\n"
      for warning in "${warnings[@]}"; do
        report+="⚠ $warning\n"
      done
    fi
  fi
  
  log_action "Проверка целостности: ${#issues[@]} ошибок, ${#warnings[@]} предупреждений"
  cls
  print_header "Проверка целостности системы"
  echo -e "$report"
  echo
  read -p "Нажмите Enter для продолжения..."
  
  return ${#issues[@]}
}

# --- Шаг 13/10: Установка BBR3 и завершение мастера ---
step_bbr3_install_and_exit() {
  cls
  print_header "Шаг 13/13 — Установка BBR3"
  echo "После установки скрипт завершится,"
  echo "а установщик BBR предложит перезагрузку."
  echo
  
  if ! ask_yesno "Запустить установку BBR3 сейчас?" "y"; then
    return 0
  fi

  cls
  echo -e "\nЗапускаю установщик BBR3. После его завершения мастер выйдет.\nЕсли установщик попросит перезагрузку — соглашаемся.\n"
  log_action "Запуск установщика BBR3"
  
  # Для BBR3 используем прямой вызов, т.к. он интерактивный и должен завершить скрипт
  local script_content
  script_content=$(curl -fsS4 https://raw.githubusercontent.com/opiran-club/VPS-Optimizer/main/bbrv3.sh 2>&1)
  if [[ $? -eq 0 ]] && [[ -n "$script_content" ]]; then
    echo "$script_content" | bash -s --ipv4 || true
    log_action "Установщик BBR3 завершён"
  else
    log_action "ОШИБКА: Не удалось загрузить установщик BBR3"
    echo "❌ Ошибка: Не удалось загрузить установщик BBR3. Проверьте подключение к интернету."
  fi
  
  echo -e "\nМастер завершён. Продолжай по инструкциям установщика BBR (перезагрузка).\n"
  log_action "=== Завершение autosettings.sh $(date) ==="
  exit 0
}

main() {
  require_root
  init_logging
  init_backup_dir
  log_action "Инициализация: логи в $LOG_FILE, резервные копии в $BACKUP_DIR"
  
  cls
  print_header "Мастер настройки Ubuntu Server"
  echo "Интерактивный мастер. После каждого шага — очистка экрана."
  echo "Логи: $LOG_FILE"
  echo "Резервные копии: $BACKUP_DIR"
  echo
  read -p "Нажмите Enter для продолжения..."
  
  # Проверка интернета (предупреждение, но не блокируем)
  if ! check_internet; then
    log_action "ПРЕДУПРЕЖДЕНИЕ: Нет подключения к интернету, некоторые шаги могут не работать"
    echo
    print_header "⚠ ПРЕДУПРЕЖДЕНИЕ"
    echo "Обнаружены проблемы с подключением к интернету."
    if ! ask_yesno "Продолжить выполнение?" "n"; then
      log_action "Пользователь отменил выполнение из-за отсутствия интернета"
      exit 0
    fi
  fi

  # Проверка системных требований
  check_system_prerequisites
  
  log_action "Начало выполнения шагов мастера"
  step_hostname_tz;            cls
  step_ssh_hardening;          cls
  step_create_user;            cls
  step_updates_now;            cls
  step_configure_swap;         cls
  step_components;             cls
  step_fail2ban_basic;         cls
  step_unattended;             cls
  step_journald_limits;        cls
  step_motd_custom;            cls
  step_sysctl_unlimit;         cls
  step_ssh_additional_hardening; cls
  
  # Проверка целостности перед завершением
  check_system_integrity
  
  step_bbr3_install_and_exit
  
  log_action "=== Завершение autosettings.sh $(date) ==="
  local duration=$(( $(date +%s) - SCRIPT_START_TIME ))
  cls
  print_header "Завершено"
  echo "Все шаги выполнены."
  echo "Время выполнения: ${duration} сек"
  echo "Логи: $LOG_FILE"
  echo
}

main "$@"
