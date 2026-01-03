FROM maven:3.8.5-eclipse-temurin-17

USER root

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    git \
    curl \
    wget  \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# -------------------------Docker CLI officiel (pas le daemon)---------------------------------------------------
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
 && echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian bookworm stable" \
  > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

 #----------------------------------- install trivy----------------------------------------------------------------

RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
 | gpg --dearmor \
 | tee /usr/share/keyrings/trivy.gpg > /dev/null

RUN echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
https://aquasecurity.github.io/trivy-repo/deb \
$(. /etc/os-release && echo $VERSION_CODENAME) main" \
> /etc/apt/sources.list.d/trivy.list

RUN apt-get update \
 && apt-get install -y trivy \
 && rm -rf /var/lib/apt/lists/*

 # Mise de la base de donnee trivy

 RUN trivy image --download-db-only

 # Vérification
RUN trivy --version

# ------------------------------------ Syft --------------------------------------------------------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
 | sh -s -- -b /usr/local/bin

# verification syft
RUN syft version

# ----------------------------------- Cosign -----------------------------------------------------------------------
RUN curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
 && mv cosign-linux-amd64 /usr/local/bin/cosign \
 && chmod +x /usr/local/bin/cosign

# verification cosign
RUN cosign version

USER jenkins
WORKDIR /home/jenkins

ENTRYPOINT ["tail", "-f", "/dev/null"]

