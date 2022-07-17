FROM    python:alpine

ENV     username=
ENV     password=
ENV     timezone=Asia/Hong_Kong

COPY    ./redis_surfshark.py /usr/python/redis_surfshark.py
COPY    ./entrypoint.sh /entrypoint.sh

RUN     apk add --no-cache wireguard-tools at && \
        pip install redis requests pytz

ENTRYPOINT ["/entrypoint.sh"]