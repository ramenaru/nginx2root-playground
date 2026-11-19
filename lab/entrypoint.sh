#!/bin/sh
set -eu

role=${LAB_ROLE:-hardened}
cp "/lab/${role}/nginx.conf" /etc/nginx/nginx.conf

if [ "$role" = "vulnerable" ]; then
    chmod 666 /etc/nginx/nginx.conf
    chmod 644 /etc/nginx/certs/lab.key
    chmod 777 /usr/sbin/nginx
    chmod 777 /var/www/lab
    printf 'add_header X-Lab-Extra "yes";\n' > /tmp/lab-extra.conf
    chmod 666 /tmp/lab-extra.conf
    printf 'lab:%s\n' "$(openssl passwd -apr1 lab)" > /etc/nginx/.htpasswd
    chmod 644 /etc/nginx/.htpasswd
    printf '<h1>vulnerable lab</h1>\n' > /var/www/lab/index.html
    mkdir -p /var/www/lab/files
    printf 'public file\n' > /var/www/lab/files/readme.txt
else
    chown root:root /etc/nginx/nginx.conf
    chmod 644 /etc/nginx/nginx.conf
    chmod 600 /etc/nginx/certs/lab.key
    printf '<h1>hardened lab</h1>\n' > /var/www/lab/index.html
    chown -R root:root /var/www/lab
    chmod 755 /var/www/lab
    chmod 644 /var/www/lab/index.html
fi

exec "$@"
