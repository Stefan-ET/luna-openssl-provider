#!/bin/bash

# This script builds the project inside a Docker image.
# For users who don't want to spend time on environment setup.

# Global variables
DOCKER_NAME="lunabuilder"
DOCKER_OS="ubi" # Red Hat Universal Base Image
DOCKER_ARCH="amd64"
DOCKER_IMG="$DOCKER_NAME.$DOCKER_OS.$DOCKER_ARCH"
DOCKER_RUNNER="docker run --rm -t -v $(dirname $0):/home/luna/luna-openssl-provider $DOCKER_IMG"
OPENSSL_VERSION="3.4.1"
OPENSSL_TAR="openssl-$OPENSSL_VERSION.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-3.5.0/$OPENSSL_TAR"
LIBOQS_VERSION="0.12.0"
LIBOQS_TAR="$LIBOQS_VERSION.tar.gz"
LIBOQS_URL="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$LIBOQS_TAR"

function usage() {
	echo "Builds the Luna OpenSSL provider, Gem Engine, and sautil inside a Docker container."
	echo
	echo "Usage: $0 [--rebuild]"
	echo "  --rebuild | -r : Quickly rebuild the Luna artifacts without downloading dependencies and rebuilding the Docker image."
	echo "  --help | -h : Show this help message."
	echo "  If not specified, the script will build the Docker image, download and build dependencies, and then build the Luna artifacts."
}

function download_deps() {
	curl -o $(dirname $0)/openssl-source/$OPENSSL_TAR -L $OPENSSL_URL
	curl -o $(dirname $0)/openssl-source/liboqs-$LIBOQS_TAR -L $LIBOQS_URL
}

function build_image() {
	docker build -t $DOCKER_IMG .
}

function clean() {
	$DOCKER_RUNNER ./build.sh SA64client clean all
}

function build_luna() {
	$DOCKER_RUNNER ./build.sh SA64client build $1
}

function pack_tarball() {
	tar -czf luna.tar.gz -C $(dirname $0) builds
}

case "$1" in
    "rebuild" | "--rebuild" | "-r")
        CLEAN_BUILD=0
	;;
    "help" | "--help" | "-h")
        usage
        exit 1
        ;;
    *)
        CLEAN_BUILD=1
        ;;
esac

if [ $CLEAN_BUILD -eq 1 ]; then
    download_deps
    build_image
    clean
    build_luna depends
fi

build_luna all
pack_tarball
