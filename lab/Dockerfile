ARG BASE_IMAGE=nginx:alpine
FROM ${BASE_IMAGE}

RUN apk add --no-cache bash openssl curl iproute2

RUN mkdir -p /etc/nginx/certs /var/www/lab \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
         -keyout /etc/nginx/certs/lab.key \
         -out /etc/nginx/certs/lab.crt \
         -subj "/CN=localhost" \
         -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
    && chmod 600 /etc/nginx/certs/lab.key

COPY n2rpg.sh /usr/local/bin/n2rpg
COPY lab/entrypoint.sh /usr/local/bin/lab-entrypoint
RUN chmod 755 /usr/local/bin/n2rpg /usr/local/bin/lab-entrypoint

ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
CMD ["nginx", "-g", "daemon off;"]
