FROM registry.access.redhat.com/ubi8/ubi

#USER root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN \
    # Upgrade all current packages
    dnf -y update --setopt=tsflags=nodocs --setopt=install_weak_deps=0 --refresh && \
    dnf -y install --setopt=tsflags=nodocs --setopt=install_weak_deps=0 \
    gcc make perl cmake
RUN \
    # Create user and group
    groupadd -g 501 app && \
    useradd -u 1000 -g app -G app -s /bin/bash luna

# Switch to luna user: if execution required to be root, then it should be stated manually, at container run time
USER luna
WORKDIR /home/luna/luna-openssl-provider

ENTRYPOINT []
CMD ["/bin/bash", "-l"]
