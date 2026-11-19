FROM nginx:alpine
RUN apk add --no-cache bash openssl curl iproute2
RUN mkdir -p /etc/nginx/certs \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
         -keyout /etc/nginx/certs/test.key \
         -out /etc/nginx/certs/test.crt \
         -subj "/CN=localhost" \
         -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1 \
    && chmod 600 /etc/nginx/certs/test.key
COPY tests/docker/nginx.conf /etc/nginx/nginx.conf
COPY n2rpg.sh /usr/local/bin/n2rpg
RUN chmod 755 /usr/local/bin/n2rpg
