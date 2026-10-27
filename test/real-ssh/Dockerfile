ARG NODE_IMAGE=node:22-bookworm@sha256:c601a46abb4d2ab80a9dc3da208d50d1122642d53f17a101926ace71e5a9bf1c
FROM ${NODE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-sftp-server dropbear python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash synthetic \
    && printf 'synthetic:synthetic-fixture-password\n' | chpasswd \
    && mkdir -p /run/sshd \
    && ln -sf /usr/lib/openssh/sftp-server /usr/lib/sftp-server
COPY test/real-ssh/entry.sh /usr/local/bin/sshops-fixture
RUN sed -i 's/\r$//' /usr/local/bin/sshops-fixture && chmod 755 /usr/local/bin/sshops-fixture
ENTRYPOINT ["/bin/sh", "/usr/local/bin/sshops-fixture"]
