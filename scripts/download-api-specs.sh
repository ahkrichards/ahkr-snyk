#!/bin/bash
# 
# TODO(ahkrichards): Description of contents

DOWNLOADS_PATH="./static/snyk-api"
API_V1_PATH="$DOWNLOADS_PATH/api-v1"
API_DESC_DOC_FILE="api-description-document"
REST_API_PATH="$DOWNLOADS_PATH/rest-api"

ANSI_COLOR_RED=$(tput setaf 1)
ANSI_COLOR_GREEN=$(tput setaf 2)
ANSI_COLOR_YELLOW=$(tput setaf 3)
ANSI_COLOR_DARK_GRAY=$(tput setaf 8)
ANSI_COLOR_NONE=$(tput sgr0)


#######################################
# Print colored formatted message to STDOUT.
# Globals:
#   ANSI_COLOR_NONE
# Arguments:
#   An ANSI color code string.
#   A message string.
# Outputs:
#   Writes a colored formatted message to STDOUT.
#######################################
function _print_with_color() {
    local color="$1"
    local msg="$2"

    printf "%s\n" "$color$msg$ANSI_COLOR_NONE"
}


#######################################
# Print error colored formatted message to STDERR.
# Globals:
#   ANSI_COLOR_RED
# Arguments:
#   A message string.
# Outputs:
#   Writes an error colored formatted message to STDERR.
#######################################
function print_error() {
    local msg="$1"
    _print_with_color "$ANSI_COLOR_RED" "$msg"
}


#######################################
# Print success colored formatted message to STDOUT.
# Globals:
#   ANSI_COLOR_GREEN
# Arguments:
#   A message string.
# Outputs:
#   Writes an success colored formatted message to STDOUT.
#######################################
function print_success() {
    local msg="$1"
    _print_with_color "$ANSI_COLOR_GREEN" "$msg"
}


#######################################
# Print info colored formatted message to STDOUT.
# Globals:
#   ANSI_COLOR_NONE
# Arguments:
#   A message string.
# Outputs:
#   Writes an info colored formatted message to STDOUT.
#######################################
function print_info() {
    local msg="$1"
    _print_with_color "$ANSI_COLOR_YELLOW" "$msg"
}


#######################################
# Print debug colored formatted message to STDOUT.
# Globals:
#   ANSI_COLOR_DARK_GRAY
# Arguments:
#   A message string.
# Outputs:
#   Writes an debug colored formatted message to STDOUT.
#######################################
function print_debug() {
    local msg="$1"
    _print_with_color "$ANSI_COLOR_DARK_GRAY" "$msg"
}


#######################################
# Print formatted message to STDOUT.
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes debug message to STDOUT.
#######################################
debug() {
  if [ ! -v DEBUG ]; then
    return 0
  fi

  #echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')|DEBUG]: $*"
  print_debug "[$(date +'%Y-%m-%dT%H:%M:%S%z')|download-api-specs|DEBUG]: $*"
}


#######################################
# Print info formatted message to STDOUT.
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes info message to STDOUT.
#######################################
info() {
  if [ ! -v DEBUG ]; then
    return 0
  fi

  #echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')|DEBUG]: $*"
  print_info "[$(date +'%Y-%m-%dT%H:%M:%S%z')|download-api-specs|INFO]: $*"
}


#######################################
# Print formatted message to STDERR.
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes error message to STDERR.
#######################################
err() {
  #echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')|ERROR]: $*" >&2
  print_error "[$(date +'%Y-%m-%dT%H:%M:%S%z')|download-api-specs|ERROR]: $*" >&2
}


#######################################
# Get name of latest downloaded API Description Document.
# Globals:
#   API_V1_PATH
#   API_DESC_DOC_FILE
# Arguments:
#   None
# Outputs:
#   Writes relative path to latest API Description Document.
# Returns:
#   0 if latest API Description Document found.
#   1 if API Description Document not yet downloaded.
#######################################
function get_latest_api_desc_doc() {
    read -r -a files <<< "$(find "$API_V1_PATH" -type f -name "$API_DESC_DOC_FILE.*.md" | sort -r)"
    if [ -z "${files[0]}" ]; then
        err "Could not find any API Description Documents! First download the latest specification..."
        return 1
    fi

    local latest_file="${files[0]}"
    echo "$latest_file"
    return 0
}


#######################################
# Checks if the latest downloaded API Description Document is written to reserved latest location.
# Globals:
#   API_V1_PATH
#   API_DESC_DOC_FILE
# Arguments:
#   File path to latest downloaded API Description Document.
# Returns:
#   1 if the file path to latest downloaded API Description Document is not provided.
#   2 if the API Description Document reserved location does not yet exist.
#   3 if the checksum could not be calculated for the lateset API Description Document.
#   4 if the checksum could not be calculated for the reserved API Description Document.
#   255 if the checksums do not match, meaning the API Description Document is not up-to-date.
#######################################
function is_up_to_date_api_desc_doc() {
    local args=("$@")
    if [[ "${#args[@]}" -eq 0 ]]; then
        err "Missing function argument! Provide file path to latest downloaded API Description Document..."
        return 1
    fi

    if [ ! -e "$API_V1_PATH/$API_DESC_DOC_FILE" ]; then
        err "Could not find the reservered API Description Document! First download the latest specification..."
        return 2
    fi

    local latest_api_desc_doc_file="${args[0]}"
    local latest_checksum=""
    if ! latest_checksum=$(sha256sum "$latest_api_desc_doc_file" | awk -F' ' '{print $1}'); then
        err "Failed to calculate checksum for latest API Description Document! (path='$latest_api_desc_doc_file')"
        return 3
    fi

    local reserved_file="$API_V1_PATH/$API_DESC_DOC_FILE"
    local reserved_checksum=""
    if ! reserved_checksum=$(sha256sum "$reserved_file" | awk -F' ' '{print $1}'); then
        err "Failed to calculate checksum for reserved API Description Document! (path='$reserved_file')"
        return 4
    fi

    debug "Checking if API Description Document is up-to-date..."
    print_debug "  Latest Checksum: $latest_checksum ($latest_api_desc_doc_file)"
    print_debug "Reserved Checksum: $reserved_checksum ($reserved_file)"

    
    # [[ "$latest_checksum" -eq "$reserved_checksum" ]]
    if [ "$latest_checksum" == "$reserved_checksum" ]; then
        return 0
    fi

    return 255
}


#######################################
# Get name of latest downloaded API Description Document.
# Globals:
#   API_V1_PATH
#   API_DESC_DOC_FILE
# Arguments:
#   None
#######################################
function download_api_desc_doc() {
    echo "--- Downloading Snyk API V1 API Description Document"
    curl \
        --silent \
        --output "$API_V1_PATH/$API_DESC_DOC_FILE.tmp" \
        "https://snyk.docs.apiary.io/api-description-document"

    local latest_api_desc_doc_file=""
    if ! latest_api_desc_doc_file=$(get_latest_api_desc_doc); then
        exit
    fi

    debug "Found latest downloaded API Description Document: '$latest_api_desc_doc_file'"
    if ! is_up_to_date_api_desc_doc "$latest_api_desc_doc_file"; then
        case $? in
            2)
                err "This is awkward... somehow we downloaded the latest API Description Document, but no longer can find it! Expected at: '$latest_api_desc_doc_file'"
                ;;
        esac

        info "API Description Document out-of-date. Updating..."
        cp -f "$latest_api_desc_doc_file" "$API_V1_PATH/$API_DESC_DOC_FILE"
    fi

    rm -f "$API_V1_PATH/$API_DESC_DOC_FILE.tmp"
}

# Globals:
#   BIN_JQ
function download_rest_openapi_spec() {
    echo "--- Downloading Snyk REST OpenAPI Specification"
    response=($( \
        curl \
            --silent \
            -X GET \
            "https://api.snyk.io/rest/openapi" \
        | $BIN_JQ '.[] | select(. | contains("~") | not)' -r \
    ))

    for version in "${response[@]}"; do
        spec_file="$REST_API_PATH/$version.json"
        if [ -e "$spec_file" ]; then
            debug "Already have Snyk REST OpenAPI Specification $version. Skipping..."
            continue
        fi

        info "Downloading Snyk REST OpenAPI Specification $version..."
        curl \
            --silent \
            -X GET \
            "https://api.snyk.io/rest/openapi/$version" \
            -H "accept: application/json" \
        | jq '.' > "$spec_file"
    done
}


BIN_JQ="/usr/bin/jq"
if ! which "$BIN_JQ"; then
    info "Runtime dependency 'jq' not found in user installation... Checking PATH..."
    if ! BIN_JQ=$(which "jq"); then
        error "Runtime dependency 'jq' not found in PATH... Please install jq!"
        exit 1
    fi

    debug "Found runtime dependency 'jq' in PATH: '$BIN_JQ'"
fi

download_api_desc_doc
download_rest_openapi_spec
