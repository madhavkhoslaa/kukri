FROM archlinux:base

RUN pacman -Syu --noconfirm --needed iperf3 iproute2 iptables nftables python libelf zlib zstd libgcc \
    && pacman -Scc --noconfirm

COPY kukri /usr/local/bin/kukri
COPY kukri.json /opt/metrics/kukri.json
COPY bench.py /opt/metrics/bench.py

ENV TERM=xterm
CMD ["python", "/opt/metrics/bench.py"]
