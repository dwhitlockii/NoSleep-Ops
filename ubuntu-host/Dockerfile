FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    iptables \
    tcpdump \
    auditd \
    rkhunter \
    chkrootkit \
    fail2ban \
    clamav \
    clamav-daemon \
    net-tools \
    curl \
    wget \
    iproute2 \
    vim \
    whois \
    rsyslog \
    logrotate \
    gpg \
    cron \
    logwatch \
    git \
    python3 \
    python3-pip \
    python3-pandas \
    gnupg \
    gnuplot \
    && apt-get clean

# Create necessary directories and files for services
RUN mkdir -p /var/log/audit && \
    touch /var/log/auth.log && \
    touch /var/log/syslog

CMD ["/bin/bash"]
