#!/bin/sh -ue

usage()
{
  printf -- 'usage: %s [-h] [-f] [-u] [-r] [-s] [-d TARGETPATH] [DIR ...]\n' "$(basename "${0}")"
  printf -- '\n'
  printf -- 'Create info files with analysis data of package files.\n'
  printf -- '\n'
  printf -- 'positional arguments:\n'
  printf -- '  DIR  Path to directory to process\n'
  printf -- '\n'
  printf -- 'optional arguments:\n'
  printf -- '  -h   Show this help message and exit\n'
  printf -- '  -f   Create analysis data for package files (*.pkg) in directories\n'
  printf -- '  -u   Create analysis data from URLs of file _analysis_urls.txt in directories\n'
  printf -- '  -r   Replace default directories with dirs instead of appending these\n'
  printf -- '  -s   Show processed file or URL\n'
  printf -- '  -d   Decrypt file to specified target path\n'
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
  local HELP DOFILES DOURLS REPLACEDIRS SHOW DECRYPT
  local DEFAULTDIRS DIRS DIR
  local URLSFILE URL FILE ERRORLOG RUNDATE EXTRA1 EXTRA2A EXTRA2B EXTRA2C

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
     ('f') set_variable DOFILES 1 ;;
     ('u') set_variable DOURLS 1 ;;
     ('r') set_variable REPLACEDIRS 1 ;;
     ('s') set_variable SHOW 1 ;;
     ('d') set_variable DECRYPT "${OPTARG}" ;;
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
  if [ "${DOFILES:-0}" -eq 0 -a "${DOURLS:-0}" -eq 0 ]
   then
    printf -- '[ERROR] Please specify -f and/or -u\n'
    HELP=1
  fi
  #
  [ "${HELP:-0}" -eq 0 ] || usage

  ## Process directories
  for DIR in ${DIRS:-} "${@}"
   do
    if [ ! -d "${DIR}" ]
     then
      printf -- '[ERROR] Directory "%s" does not exist\n' "${DIR}"
      continue
    fi
    [ -d "${DIR}/_pkginfo" ] || mkdir "${DIR}/_pkginfo"
    #
    ## Analyse packages from URL
    URLSFILE="${DIR}/_analysis_urls.txt"
    if [ "${DOURLS:-0}" -eq 1 -a -s "${URLSFILE}" ]
     then
      ERRORLOG="${DIR}/_error_url.log"
      RUNDATE="$(date +'%Y-%m-%d %H:%M:%S')"
      #
      printf -- '[%s] >>>>> Creating analysis data for URLs in "%s"...\n' "${RUNDATE}" "${URLSFILE}"
      [ ! -s "${ERRORLOG}" ] || rm "${ERRORLOG}"
      for URL in $(cat "${URLSFILE}")
       do
        [ -n "${URL}" ] || continue
        #
        ## additional `printf` to see currently processed url
        [ "${SHOW:-0}" -eq 0 ] || printf -- '%s\n' "${URL}"
        #
        { PSN_get_pkg_info.py --itementries --unknown -f 99 -- "${URL}" 3>&1 1>"${DIR}/_pkginfo/$(basename "${URL}").info" 2>&3 | tee -a "${ERRORLOG}" ; } || true
      done
      [ ! -s "${ERRORLOG}" ] || sed -i -e "1 i[${RUNDATE}] >>>>> Errors during analysis data creation for URLs in ${URLSFILE}..." "${ERRORLOG}"
    fi  ## URLs
    #
    ## Analyse packages from package files
    if [ "${DOFILES:-0}" -eq 1 ]
     then
      ERRORLOG="${DIR}/_error.log"
      RUNDATE="$(date +'%Y-%m-%d %H:%M:%S')"
      #
      printf -- '[%s] >>>>> Creating analysis data for package files in "%s"...\n' "${RUNDATE}" "${DIR}"
      [ ! -s "${ERRORLOG}" ] || rm "${ERRORLOG}"
      ## additional `-print` to see currently processed file
      [ "${SHOW:-0}" -eq 0 ] || EXTRA1='-print'
      ## additional `--raw ./decrypted.pkg --overwrite` to find gaps
      if [ -n "${DECRYPT:-}" ]
       then
        EXTRA2A='--raw'
        EXTRA2B="${DECRYPT}"
        EXTRA2C='--overwrite'
      fi
      #
      #export DIR
      #export ERRORLOG
      #{ printf '' | xargs -- find "${DIR}" -type f -name '*.pkg' ${EXTRA1:-} -exec sh -c 'PSN_get_pkg_info.py --itementries --unknown -f 99 -- "${1}" 3>&1 1>"${DIR}/_pkginfo/$(basename "${1}").list" 2>&3 | tee -a "${ERRORLOG}"' -- '{}' \; ; } || true
      { printf '' | xargs -- find "${DIR}" -type f -name '*.pkg' ${EXTRA1:-} -exec sh -c "PSN_get_pkg_info.py --itementries --unknown -f 99 ${EXTRA2A:-} ${EXTRA2B:-} ${EXTRA2C:-} -- \"\${1}\" 3>&1 1>\"${DIR}/_pkginfo/\$(basename \"\${1}\").info\" 2>&3 | tee -a \"${ERRORLOG}\"" -- '{}' \; ; } || true
      [ ! -s "${ERRORLOG}" ] || sed -i -e "1 i[${RUNDATE}] >>>>> Errors during analysis data creation for package files in ${DIR}..." "${ERRORLOG}"
    fi  ## Files
  done  ## DIR

  return 0  ## leave function
}

main "${@}"
