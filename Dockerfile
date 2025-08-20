##############################################################################
#
# This file is part of the "Luna OpenSSL for PQC" project.
#
# The " Luna OpenSSL for PQC " project is provided under the MIT license (see the
# following Web site for further details: https://mit-license.org/ ).
#
# Copyright © 2025 Thales Group
#
##############################################################################
#
# Description:
#   This Dockerfile is used to build a container image for the "Luna OpenSSL for PQC" project.

FROM registry.access.redhat.com/ubi8/ubi

ARG UID
ARG GID

#USER root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN \
    # Upgrade all current packages
    dnf -y update --setopt=tsflags=nodocs --setopt=install_weak_deps=0 --refresh && \
    dnf -y install --setopt=tsflags=nodocs --setopt=install_weak_deps=0 \
    gcc make perl cmake
RUN \
    # Create user and group
    groupadd -g "${GID}" luna && \
    useradd -u "${UID}" -g luna -G luna -s /bin/bash luna

# Switch to luna user: if execution required to be root, then it should be stated manually, at container run time
USER luna
WORKDIR /home/luna/luna-openssl-provider

ENTRYPOINT []
CMD ["/bin/bash", "-l"]
