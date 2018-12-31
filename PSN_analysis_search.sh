#!/bin/sh -ue

usage()
{
  printf -- 'usage: %s [-h] [-r] [DIR ...]\n' "$(basename "${0}")"
  printf -- '\n'
  printf -- 'Search info files with analysis data of package files.\n'
  printf -- '\n'
  printf -- 'positional arguments:\n'
  printf -- '  dir  Path to directory to process\n'
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
  local IFS OLDIFS TABIFS
  local GREP GREP_OUTPUT UNIQUE GREP_DISPLAY FILELIST NEWFILELIST
  local MAXCOUNT COUNT
  MAXCOUNT=99
  #
  for COUNT in $(seq 1 "${MAXCOUNT}")
   do
    local "$(eval printf -- 'GREP_${COUNT}')"
    unset "$(eval printf -- 'GREP_${COUNT}')"
  done
  #
  OLDIFS="${IFS}"
  TABIFS="$(printf -- '\t')"

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
  while getopts 'hfursd:' OPTION
   do
    case "${OPTION}" in
     ('h'|'?') HELP=1 ;;
     ('r') set_variable REPLACEDIRS 1 ;;
    esac
  done
  shift $(( ${OPTIND} - 1))

  ## Process positional parameters
  if [ "${REPLACEDIRS:-0}" -eq 1 ]
   then
    unset DIRS
    if [ "${#}" -le 0 ]
     then
      printf -- '[ERROR] No directories stated\n'
      HELP=1
    fi
  fi

  ## Check options
  [ "${HELP:-0}" -eq 0 ] || usage

  ## Define multiple grep patterns GREP_<n> with options to determine the wanted package info files
  ##   To INCLUDE matching files use '-l' (lower case) as the first parameter
  ##   To EXCLUDE matching files use '-L' (upper case) as the first parameter
  ## Define grep pattern GREP_OUTPUT for the final result output
  ##   -l/-L will be removed, so GREP_<n> can be re-used
  ## Separate parameters with TAB (TAB will be used as IFS on grep commands)
  set +u
  ##
  ## Examples:
  ## GREP_1='-l	-e	^headerfields\[\"TYPE\".*:.* = 0x1$'
  ## GREP_OUTPUT="${GREP_1:+${GREP_1}	}-e	^headerfields\\[\\\"HDRSIZE\\\".*"
  #
  ## PKG3 Header Types: TYPE
  #GREP_OUTPUT="-e	^headerfields\\[\\\"TYPE\\\".*"
  #UNIQUE=1
  #
  ## PKG3 Header Type 1 or 2: HDRSIZE
  #GREP_1='-l	-e	^headerfields\[\"TYPE\".*:.* = 0x1$'
  #GREP_1='-l	-e	^headerfields\[\"TYPE\".*:.* = 0x2$'
  #GREP_2='-l	-e	^headerfields\[\"MAGIC\".*:.* = 0x7f504b47$'
  #GREP_OUTPUT="-e	^headerfields\\[\\\"HDRSIZE\\\".*"
  #UNIQUE=1
  #
  ## KEYINDEX
  #GREP_OUTPUT="-o	-e	KEYINDEX.*: [[:digit:]]*	-e	Key Index [[:digit:]]*"
  #UNIQUE=1

  ## Clean-up and check GREP_OUTPUT pattern
  set -u
  GREP_OUTPUT="$(printf -- '%s' "${GREP_OUTPUT:-}" | sed -r -e 's#(-l|-L)##g ; s#[\t]+#\t#g ; s#(^\t|\t$)##g')"
  #
  if [ -z "${GREP_OUTPUT:-}" ]
   then
    printf -- '[ERROR] No OUTPUT grep pattern defined\n'
    return 0
  fi

  ## Process directories
  for DIR in ${DIRS:-} "${@}"
   do
    if [ ! -d "${DIR}" ]
     then
      printf -- '[ERROR] Directory "%s" does not exist\n' "${DIR}"
      continue
    fi
    [ -d "${DIR}/_pkginfo" ] || continue
    #
    printf -- '# >>>>> Searching analysis data in ${DIR} for grep patterns...\n'

    ## Determine package info files for output via GREP_<n> patterns
    ## --> Starting file list
    [ -d "${DIR}/_tmp" ] || mkdir "${DIR}/_tmp"
    FILELIST="$(tempfile -d "${DIR}/_tmp")"
    printf -- '%s' "${DIR}/_pkginfo" >"${FILELIST}"
    ## --> Process GREP_<n> patterns
    for COUNT in $(seq 1 "${MAXCOUNT}")
     do
      [ -s "${FILELIST}" ] || break
      #
      eval GREP=\"\${GREP_${COUNT}:-}\"
      [ -n "${GREP}" ] || break
      printf -- '# > Grep %s: %s\n' "${COUNT}" "${GREP}" | sed -e 's#\t# #g'
      #
      NEWFILELIST="$(tempfile -d "${DIR}/_tmp")"
      IFS="${TABIFS}"
      #set -x
      { cat -- "${FILELIST}" | xargs -0 -r -L 10 -- grep -R -Z ${GREP} -- >"${NEWFILELIST}" ; } || :
      #set +x
      IFS="${OLDIFS}"
      #
      rm "${FILELIST}"
      FILELIST="${NEWFILELIST}"
      #
      [ -s "${FILELIST}" ] || break
      #cat -- "${FILELIST}" | xargs -0 -r -L 1
    done  ## COUNT

    ## Show wanted output of remaining package info files via GREP_OUTPUT pattern
    if [ ! -s "${FILELIST}" ]
     then
      [ ! -e "${FILELIST}" ] || rm "${FILELIST}"
      printf -- 'No matches\n'
    else
      printf -- '# > Grep OUTPUT: %s\n' "${GREP_OUTPUT}" | sed -e 's#\t# #g'
      #
      IFS="${TABIFS}"
      #set -x
      if [ "${UNIQUE:-0}" -eq 1 ]  ## unique values
       then
        { cat -- "${FILELIST}" | xargs -0 -r -L 10 -- grep -R -h ${GREP_OUTPUT} -- | sort | uniq -c ; } || :
      else
        { cat -- "${FILELIST}" | xargs -0 -r -L 10 -- grep -R -H ${GREP_OUTPUT} -- ; } || :
      fi
      #set +x
      IFS="${OLDIFS}"
      #
      rm "${FILELIST}"
    fi

    unset FILELIST
    printf -- '\n'
  done  ## DIR

  return 0  ## leave function
}

main "${@}"
