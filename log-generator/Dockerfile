FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    apache2 \
    rsyslog \
    cron \
    netcat \
    bash \
    && apt-get clean

COPY generate-logs.sh /usr/local/bin/generate-logs.sh
RUN chmod +x /usr/local/bin/generate-logs.sh

CMD ["/usr/local/bin/generate-logs.sh"]
