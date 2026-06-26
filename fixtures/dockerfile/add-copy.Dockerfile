FROM scratch
ADD https://downloads.example.com/archive.tar.gz /tmp/archive.tar.gz
COPY ["dist/app", "/opt/app"]
COPY --chown=1000:1000 config/app.conf /etc/app.conf
