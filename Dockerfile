FROM ccasconeonf/p4mn:latest

ENV PKG_DEPS python-pip git
RUN apt-get update && \
    apt-get install -y --no-install-recommends $PKG_DEPS && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    pip install git+https://github.com/p4lang/scapy-vxlan \
                git+https://github.com/p4lang/ptf.git && \
    rm -rf ~/.cache/pip

# Get P4Runtime python bindings from PI
COPY --from=p4lang/pi:stable /usr/local/lib/python2.7/dist-packages/p4/ /py_p4
RUN SITE_PACKAGES=$(python -c "import site; print(site.getsitepackages()[0])") && \
    mkdir -p $SITE_PACKAGES/p4/ && \
    cp -r /py_p4/* $SITE_PACKAGES/p4/

ENV DOCKER_RUN true

ENTRYPOINT []