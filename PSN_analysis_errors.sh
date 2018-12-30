#!/bin/sh -e

main()
{
  ## Localize and initialize variables
  local PLATFORMS PLATFORM ERRORLOG
  unset PLATFORMS

  ## Set variables
  if [ -n "${1}" ]
   then
    PLATFORMS="${1}"
  else
    PLATFORMS="${PLATFORMS:+${PLATFORMS} }PS3"
    PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSX"
    PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSP"
    PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSV"
    PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSM"
    #
    PLATFORMS="${PLATFORMS:+${PLATFORMS} }PS4"
  fi
  #
  if [ -n "${2}" ]
   then
    PLATFORMS="${PLATFORMS:+${PLATFORMS} }${2}"
  fi

  ## Analyse packages
  for PLATFORM in ${PLATFORMS}
   do
    [ -d "${PLATFORM}" ] || continue
    #
    ERRORLOG="${PLATFORM}/_error_url.log"
    [ ! -s "${ERRORLOG}" ] || cat "${ERRORLOG}"
    #
    ERRORLOG="${PLATFORM}/_error.log"
    [ ! -s "${ERRORLOG}" ] || cat "${ERRORLOG}"
  done  ## PLATFORM
}

main "${@}"
