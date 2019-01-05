#!/bin/sh -ue

usage()
{
  printf -- 'usage: %s [-h] [-r] [DIR ...]\n' "$(basename "${0}")"
  printf -- '\n'
  printf -- 'List error logs of info files creation.\n'
  printf -- '\n'
  printf -- 'positional arguments:\n'
  printf -- '  DIR  Path to directory to process\n'
  printf -- '\n'
  printf -- 'optional arguments:\n'
  printf -- '  -h   Show this help message and exit\n'
  printf -- '  -r   Replace default directories with dirs instead of appending these\n'
  printf -- '\n'
  printf -- 'default directories:\n'
  printf -- '  %s\n' "${DEFAULTDIRS}"
  exit 2
}

set_variable()
{
  local VARNAME VALUE

  VARNAME="${1}"
  shift
  #
  eval VALUE=\"\${${VARNAME}:-}\"
  if [ -z "${VALUE}" ]
   then
    eval "${VARNAME}=\"$@\""
  else
    printf -- '[ERROR] %s already set\n' "${VARNAME}"
    HELP=1
  fi
}

main()
{
  ## Localize and initialize variables
  local OPTION OPTARG OPTIND
  local HELP REPLACEDIRS
  local DEFAULTDIRS DIRS DIR
  local ERRORLOG

  ## Set default directories
  unset DEFAULTDIRS
  DEFAULTDIRS="${DEFAULTDIRS:+${DEFAULTDIRS} }PS3"
  DEFAULTDIRS="${DEFAULTDIRS:+${DEFAULTDIRS} }PSX"
  DEFAULTDIRS="${DEFAULTDIRS:+${DEFAULTDIRS} }PSP"
  DEFAULTDIRS="${DEFAULTDIRS:+${DEFAULTDIRS} }PSV"
  DEFAULTDIRS="${DEFAULTDIRS:+${DEFAULTDIRS} }PSM"
  #
  DEFAULTDIRS="${DEFAULTDIRS:+${DEFAULTDIRS} }PS4"
  #
  DIRS="${DEFAULTDIRS}"

  ## Process command line options
  while getopts 'hr' OPTION
   do
    case "${OPTION}" in
     ('h'|'?') HELP=1 ;;
     ('r') set_variable REPLACEDIRS 1 ;;
    esac
  done
  [ "${HELP:-0}" -eq 0 ] || usage
  shift $(( ${OPTIND} - 1))

  ## Process positional parameters
  if [ "${REPLACEDIRS:-0}" -eq 1 ]
   then
    unset DIRS
    if [ "${#}" -le 0 ]
     then
      printf -- '[ERROR] No directories stated\n'
      usage
    fi
  fi

  ## Process directories
  for DIR in ${DIRS:-} "${@}"
   do
    if [ ! -d "${DIR}" ]
     then
      printf -- '[ERROR] Directory "%s" does not exist\n' "${DIR}"
      continue
    fi
    #
    ERRORLOG="${DIR}/_error_url.log"
    [ ! -s "${ERRORLOG}" ] || cat "${ERRORLOG}"
    #
    ERRORLOG="${DIR}/_error.log"
    [ ! -s "${ERRORLOG}" ] || cat "${ERRORLOG}"
  done  ## DIR

  return 0  ## leave function
}

main "${@}"
