#!/bin/sh -e

main()
{
  ## Localize and initialize variables
  local IFS OLDIFS TABIFS
  local PLATFORMS PLATFORM
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


  ## Define multiple grep patterns GREP_<n> with options to determine the wanted package info files
  ##   To INCLUDE matching files use '-l' (lower case) as the first parameter
  ##   To EXCLUDE matching files use '-L' (upper case) as the first parameter
  ## Define grep pattern GREP_OUTPUT for the final result output
  ##   -l/-L will be removed, so GREP_<n> can be re-used
  ## Separate parameters with TAB (TAB will be used as IFS on grep commands)
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


  ## Clean-up and check GREP_OUTPUT pattern
  GREP_OUTPUT="$(printf -- '%s' "${GREP_OUTPUT}" | sed -r -e 's#(-l|-L)##g ; s#[\t]+#\t#g ; s#(^\t|\t$)##g')"
  if [ -z "${GREP_OUTPUT}" ]
   then
    printf -- "[ERROR] No OUTPUT grep pattern defined\n"
    return 0
  fi

  ## Process platform directories
  for PLATFORM in ${PLATFORMS}
   do
    [ -d "${PLATFORM}/_pkginfo" ] || continue
    #
    echo "# >>>>> Searching analysis data of ${PLATFORM} for grep patterns..."

    ## Determine package info files for output via GREP_<n> patterns
    ## --> Starting file list
    [ -d "${PLATFORM}/_tmp" ] || mkdir "${PLATFORM}/_tmp"
    FILELIST="$(tempfile -d "${PLATFORM}/_tmp")"
    printf -- '%s' "${PLATFORM}/_pkginfo" >"${FILELIST}"
    ## --> Process GREP_<n> patterns
    for COUNT in $(seq 1 "${MAXCOUNT}")
     do
      [ -s "${FILELIST}" ] || break
      #
      eval GREP=\"\${GREP_${COUNT}}\"
      [ -n "${GREP}" ] || break
      printf -- '# > Grep %s: %s\n' "${COUNT}" "${GREP}" | sed -e 's#\t# #g'
      #
      NEWFILELIST="$(tempfile -d "${PLATFORM}/_tmp")"
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
  done  ## PLATFORM

  return 0  ## leave function
}

main "${@}"
