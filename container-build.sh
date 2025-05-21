#!/bin/bash

# This script builds the project inside a Docker image.
# For users who don't want to spend time on environment setup.

# Global variables
DOCKER_NAME="lunabuilder"
DOCKER_OS="ubi" # Red Hat Universal Base Image
DOCKER_ARCH="amd64"
DOCKER_IMG="$DOCKER_NAME.$DOCKER_OS.$DOCKER_ARCH"
DOCKER_RUNNER="docker run --rm -t -v $(dirname $0):/home/luna/luna-openssl-provider $DOCKER_IMG"
OPENSSL_VERSION="3.5.0"
OPENSSL_TAR="openssl-$OPENSSL_VERSION.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-3.5.0/$OPENSSL_TAR"
LIBOQS_VERSION="0.10.0"
LIBOQS_TAR="$LIBOQS_VERSION.tar.gz"
LIBOQS_URL="https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$LIBOQS_TAR"

function download_deps() {
	curl -o $(dirname $0)/openssl-source/$OPENSSL_TAR -L $OPENSSL_URL
	curl -o $(dirname $0)/openssl-source/liboqs-$LIBOQS_TAR -L $LIBOQS_URL
}

function build_image() {
    docker build -t $DOCKER_IMG .
}

function build_luna() {
		$DOCKER_RUNNER ./build.sh SA64client clean all
		$DOCKER_RUNNER ./build.sh SA64client build depends
		$DOCKER_RUNNER ./build.sh SA64client build all
}

download_deps
build_image
build_luna
