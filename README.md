#!/bin/bash

read -p "Введите домен (например, site.com): " DOMAIN

# Установка пакетов
sudo apt update && sudo apt install ufw fail2ban nginx -y

# Настройка UFW
sudo ufw allow 22
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Отключение IPv6
sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Настройка Fail2Ban
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 50

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600

[nginx-botsearch]
enabled = true
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 100
bantime = 7200
EOF

sudo systemctl restart fail2ban

# Защита через iptables
sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Настройка сайта в Nginx
sudo tee /etc/nginx/sites-available/$DOMAIN > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# Секция HTTPS создастся позже Certbot-ом
EOF

# Добавление заголовков безопасности для последующего использования
sudo tee /etc/nginx/snippets/security-headers.conf > /dev/null <<EOF
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://api.web3modal.org https://*.walletconnect.com https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline'; connect-src 'self' https://api.web3modal.org https://*.walletconnect.com https://rpc.walletconnect.org https://mainnet.infura.io https://123askdjhakfuhwiefu.life wss://relay.walletconnect.org; img-src 'self' data: blob: https://api.web3modal.org https://proxy.dial.to https://imagedelivery.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; frame-src 'self' https://verify.walletconnect.org;" always;
EOF

# Активация сайта
sudo ln -s /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/ || true
sudo nginx -t && sudo systemctl reload nginx

# Установка certbot без запуска
sudo apt install certbot python3-certbot-nginx -y

echo -e "\n✅ Всё готово. Запусти теперь вручную:\n"
echo "  sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN"
echo -e "\n⚠️ Certbot сам пропишет SSL и создаст конфигурацию HTTPS."
