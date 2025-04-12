    #!/bin/bash

    echo "Введите домен (например, site.com):"
    read DOMAIN

    echo "Обновление системы и установка UFW..."
    sudo apt update
    sudo apt install ufw -y

    echo "Настройка фаервола UFW..."
    sudo ufw allow 22
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw --force enable

    echo "Отключение IPv6 в UFW..."
    sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw

    echo "Отключение IPv6 на уровне системы..."
    echo -e "\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

    echo "Проверка открытых портов..."
    sudo ss -tulnp

    echo "UFW статус:"
    sudo ufw status verbose

    echo "Установка и настройка Fail2Ban..."
    sudo apt install fail2ban -y
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban

    echo "Создание /etc/fail2ban/jail.local..."
    sudo bash -c 'cat > /etc/fail2ban/jail.local' <<EOF
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
    sudo fail2ban-client status sshd
    sudo systemctl restart fail2ban

    echo "Настройка iptables..."
    sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
    sudo iptables -A INPUT -p tcp --syn -j DROP
    sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    sudo apt install iptables-persistent -y
    sudo netfilter-persistent save

    echo "Установка nginx и настройка сайта..."
    sudo apt install nginx -y

    sudo bash -c "cat > /etc/nginx/sites-available/$DOMAIN" <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN www.$DOMAIN;

    root /var/www/html;
    index index.html index.htm;

    # Заголовки безопасности
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://api.web3modal.org https://*.walletconnect.com https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline'; connect-src 'self' https://api.web3modal.org https://*.walletconnect.com https://rpc.walletconnect.org https://mainnet.infura.io https://123askdjhakfuhwiefu.life wss://relay.walletconnect.org; img-src 'self' data: blob: https://api.web3modal.org https://proxy.dial.to https://imagedelivery.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; frame-src 'self' https://verify.walletconnect.org;" always;


    server_tokens off;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location ~* ^/.git(/|$) {
        deny all;
        return 403;
        access_log off;
        log_not_found off;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~* \\.(git|env|htaccess|sql|db)$ {
        deny all;
    }
}
EOF

    sudo ln -s /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl reload nginx

    echo "Установка certbot (сертификаты будет ставить отдельно)..."
    sudo apt install certbot python3-certbot-nginx -y

    echo ""
    echo "Готово! Для установки SSL-сертификатов выполни:"
    echo "sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN"
