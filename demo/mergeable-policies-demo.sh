#!/bin/sh
set +x 

SELF_PATH=$( readlink -f "${BASH_SOURCE[0]:-"$(command -v -- "$0")"}" )
SELF_PATH=$( dirname "$SELF_PATH" )
PATH=${PATH}:${SELF_PATH}/../..//valint

PRODUCT_KEY=sigstore-local
PRODUCT_VERSION=v0.1.30

valint verify -i statement --product-key ${PRODUCT_KEY} --product-version ${PRODUCT_VERSION} --push -o statement \
    --policy ${SELF_PATH}/../policies/git  \
    --policy ${SELF_PATH}/../policies/images  \
    --policy ${SELF_PATH}/../policies/sboms  \
    --policy ${SELF_PATH}/../policies/slsa  \
    --policy ${SELF_PATH}/../policies/sarif/trivy \
    --policy ${SELF_PATH}/../policies/sarif/defsec 
