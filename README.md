server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name yourdomain.com www.yourdomain.com;

    root /var/www/html;
    index index.html index.htm;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # 🔒 Security Headers (всё встроено сюда)
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://api.web3modal.org https://*.walletconnect.com https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline'; connect-src 'self' https://api.web3modal.org https://*.walletconnect.com https://rpc.walletconnect.org https://mainnet.infura.io https://123askdjhakfuhwiefu.life wss://relay.walletconnect.org; img-src 'self' data: blob: https://api.web3modal.org https://proxy.dial.to https://imagedelivery.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; frame-src 'self' https://verify.walletconnect.org;" always;

    server_tokens off;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location ~* ^/.git(/|$) {
        deny all;
        access_log off;
        log_not_found off;
        return 403;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~* \.(git|env|htaccess|sql|db)$ {
        deny all;
    }
}
