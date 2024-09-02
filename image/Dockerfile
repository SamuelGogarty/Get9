# syntax=docker/dockerfile:1
# Builds a clean image containing Counter-Strike 1.6 server using the latest steamcmd base image.

#FROM startersclan/steamcmd:git-20231109.0.0
FROM ubuntu:latest

ARG STEAMCMD_DIR=/steamcmd
ARG STEAMCMD_AR_URL=https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz
WORKDIR $STEAMCMD_DIR
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y \
        locales \
        ca-certificates \
        curl \
        # Game dependencies
        lib32gcc-s1 \
        lib32stdc++6 \
        lib32z1 \
        libbz2-1.0:i386 \
        libcurl3-gnutls:i386 \
        libstdc++6:i386 \
        libcurl4-gnutls-dev:i386 \
        # Game administration packages
        git \
        # Text editors
        vim-tiny \
        nano \
    && curl -sqL "$STEAMCMD_AR_URL" | tar -zxvf -

# Define the server directory
ARG SERVER_DIR=/server
ARG APP_MANIFEST_URL=https://github.com/startersclan/hlds-appmanifest/archive/refs/tags/v2.0.0.tar.gz

# Setup environment
#ENV LD_LIBRARY_PATH="${SERVER_DIR}:${LD_LIBRARY_PATH}"
ENV SERVER_DIR="${SERVER_DIR}"

WORKDIR ${SERVER_DIR}

# Install Counter-Strike 1.6 with retries and apply app manifest fix
RUN echo "[BUILD] Starting installation of Counter-Strike 1.6..."; \
    mkdir -p ${SERVER_DIR}; \
    echo "[BUILD] Downloading and applying app manifest fix..."; \
    curl -sqL "${APP_MANIFEST_URL}" | tar -zxvf - -C ${SERVER_DIR} --strip-components=2; \
    echo "[BUILD] Starting SteamCMD operations..."; \
    RETRIES=5; \
    for i in $(seq 1 $RETRIES); do \
        /steamcmd/steamcmd.sh +force_install_dir ${SERVER_DIR} +login anonymous \
        +app_set_config 90 mod cstrike +app_update 90 -beta steam_legacy validate +quit && \
        echo "[BUILD] Installation successful on attempt $i." && break || \
        echo "[BUILD] Retry $i/$RETRIES failed, retrying in 30 seconds..."; \
        sleep 30; \
    done; \
    if [ "$?" -ne 0 ]; then \
        echo "[BUILD] Failed to install after $RETRIES attempts, exiting."; \
        exit 1; \
    fi; \
    echo "[BUILD] Counter-Strike 1.6 installation complete.";

# Apply necessary library links to avoid common errors with older games
RUN echo "[BUILD] Applying library fixes..."; \
    ln -s /usr/lib/x86_64-linux-gnu/libstdc++.so.6 ${SERVER_DIR}/libstdc++.so.6; \
    ln -s /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 ${SERVER_DIR}/libgcc_s.so.1; \
    echo "[BUILD] Library fixes applied.";

# Cleanup to reduce image size
RUN echo "[BUILD] Cleaning up unnecessary files..."; \
    find ${SERVER_DIR} -type f -name "*.txt" -delete; \
    echo "[BUILD] Cleanup complete.";

COPY hlds/liblist.gam /server/cstrike/
COPY hlds/cs.so /server/cstrike/dlls/
COPY hlds/amxmodx /server/cstrike/addons/amxmodx/
COPY hlds/metamod /server/cstrike/addons/metamod/
COPY hlds/reunion /server/cstrike/addons/reunion/
COPY hlds/reunion.cfg /server/cstrike/
COPY hlds/engine_i486.so /server/
COPY hlds/libstdc++.so.6 /server/
COPY hlds/libgcc_s.so.1 /server/


RUN ./hlds_run -game cstrike +maxplayers 16 +map de_dust2 & \
    sleep 10 && \
    kill $!

# Configure entrypoint and default command
ENTRYPOINT ["./hlds_run"]
CMD ["-game", "cstrike", "+maxplayers", "16", "+map", "de_dust2"]

# Expose the default HLDS ports
EXPOSE 27015/tcp 27015/udp 27020/udp

# Display build information
RUN echo "Counter-Strike 1.6 server has been successfully installed in ${SERVER_DIR}.";
RUN echo "To run the server, use the following command:";
RUN echo "docker run -d --name cs_server -p 27015:27015 -p 27015:27015/udp -p 27020:27020/udp your_image_name";
