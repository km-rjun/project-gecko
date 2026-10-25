# Disposable OpenSSH target for development and tests.
FROM alpine:3.24

RUN apk add --no-cache openssh-server openssh-keygen bash ncurses-terminfo-base htop \
 && adduser -D -s /bin/bash devuser \
 && echo 'devuser:devpass' | chpasswd \
 && install -d -m 700 -o devuser -g devuser /home/devuser/.ssh \
 && rm -f /etc/ssh/ssh_host_*

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh gen-dev-keys.sh /usr/local/bin/

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
