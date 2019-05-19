FROM ccasconeonf/p4mn:latest

RUN pip install git+https://github.com/p4lang/scapy-vxlan \
                git+https://github.com/p4lang/ptf.git && \
    rm -rf ~/.cache/pip

ENV DOCKER_RUN true

ENTRYPOINT []