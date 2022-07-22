FROM    python:alpine

ENV     username=
ENV     password=
ENV     timezone=Asia/Hong_Kong

COPY    ./surfshark_wireguard_token.py /usr/python/surfshark_wireguard_token.py
COPY    ./entrypoint.sh /entrypoint.sh

RUN     apk add --no-cache wireguard-tools at && \
        pip install redis requests pytz && \
        chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]