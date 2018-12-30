#!/bin/sh -e

## Set variables
OLDIFS="${IFS}"
NEWLINEIFS="$(printf -- '\nX')" ; NEWLINEIFS="${NEWLINEIFS%X}"
TABIFS="$(printf -- '\t')"
#
unset PLATFORMS
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PS3"
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSX"
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSP"
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSPx"
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSV"
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSVx"
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PSM"
PLATFORMS="${PLATFORMS:+${PLATFORMS} }PS4"

## Analyse packages
for PLATFORM in ${PLATFORMS}
 do
  PLATFORMDIR="${PLATFORM}"
  [ -d "${PLATFORMDIR}/_pkginfo" ] || continue
  unset MUST_PRE_MATCH_NO_OUTPUT
  unset MUST_MATCH_OUTPUT
  unset MUST_POST_MATCH_NO_OUTPUT
  unset MUST_NOTMATCH
  unset EXTRA_OUTPUT_MATCH
  UNIQUE=0


  ## Find package info files that contain *all* arguments sets
  ## Use \n to separate argument sets, use \t to separate arguments within a set
  ## ATTENTION!!! printf substitution will take place *2 TIMES* so may have to double escape special values
  ## Example: X='-e\t^headerfields\[\"TYPE\".*:.* = 0x1$\n-e\t^headerfields\[\"HDRSIZE\".* = 0xc0$'
  #
  ## PKG3 Header Types: TYPE
  #EXTRA_OUTPUT_MATCH='-e\t^headerfields\[\"TYPE\".*'
  #UNIQUE=1
  #
  ## PKG3 Header Type 1 or 2: HDRSIZE
  #MUST_PRE_MATCH_NO_OUTPUT='-e\t^headerfields\[\"TYPE\".*:.* = 0x1$\n'
  #MUST_PRE_MATCH_NO_OUTPUT='-e\t^headerfields\[\"TYPE\".*:.* = 0x2$\n'
  #MUST_POST_MATCH_NO_OUTPUT='-e\t^headerfields\[\"MAGIC\".*:.* = 0x7f504b47$'
  #EXTRA_OUTPUT_MATCH='-e\t^headerfields\[\"HDRSIZE\".*'
  #UNIQUE=1

  if [ -z "${MUST_PRE_MATCH_NO_OUTPUT}${MUST_MATCH_OUTPUT}${MUST_POST_MATCH_NO_OUTPUT}${MUST_NOTMATCH}${EXTRA_OUTPUT_MATCH}" ]
   then
    printf -- "[ERROR] No match sets defined\n"
    break
  fi

  echo "# >>>>> Searching analysis data of ${PLATFORM} for multiple values in a single package..."
  #
  FILES="$(printf -- '%s' "${PLATFORMDIR}/_pkginfo" | base64)"
  ALLMATCHSETS=''
  ## (1a) MUST_MATCH_... grep with -l
  if [ -n "${FILES}" -a -n "${MUST_PRE_MATCH_NO_OUTPUT}${MUST_MATCH_OUTPUT}${MUST_POST_MATCH_NO_OUTPUT}" ]
   then
    IFS="${NEWLINEIFS}"
    for MATCHSET in $(printf -- "${MUST_PRE_MATCH_NO_OUTPUT}\n${MUST_MATCH_OUTPUT}\n${MUST_POST_MATCH_NO_OUTPUT}")
     do
      [ -n "${MATCHSET}" ] || continue
      IFS="${TABIFS}"
      #set -x
      MATCHSETX="$(printf -- "-l\t${MATCHSET}")"
      #
      DISPLAYMATCHSET="$(printf -- '%s' "${MATCHSETX}" "${EXTRA_OUTPUT_MATCH}" | sed -e 's#\t# #g')"
      ALLMATCHSETS="${ALLMATCHSETS:+${ALLMATCHSETS} }${DISPLAYMATCHSET}"
      #
      FILES="$(printf -- "${FILES}" | base64 -d | xargs -0 -r -L 10 -- grep -R -Z ${MATCHSETX} | base64)"
      #set +x
      #printf -- '## >>> %s:\n' "${DISPLAYMATCHSET}" ; printf -- "${FILES}" | base64 -d | xargs -0 -r -L 1
      [ -n "${FILES}" ] || break
    done
    IFS="${OLDIFS}"
  fi
  ## (1b) MUST_NOTMATCH grep with -L
  if [ -n "${FILES}" -a -n "${MUST_NOTMATCH}" ]
   then
    IFS="${NEWLINEIFS}"
    for MATCHSET in $(printf -- "${MUST_NOTMATCH}")
     do
      [ -n "${MATCHSET}" ] || continue
      IFS="${TABIFS}"
      #set -x
      MATCHSETX="$(printf -- "-L\t${MATCHSET}")"
      #
      DISPLAYMATCHSET="$(printf -- '%s' "${MATCHSETX}" "${EXTRA_OUTPUT_MATCH}" | sed -e 's#\t# #g')"
      ALLMATCHSETS="${ALLMATCHSETS:+${ALLMATCHSETS} }${DISPLAYMATCHSET}"
      #
      FILES="$(printf -- "${FILES}" | base64 -d | xargs -0 -r -L 10 -- grep -R -Z ${MATCHSETX} | base64)"
      #set +x
      #printf -- '## >>> %s:\n' "${DISPLAYMATCHSET}" ; printf -- "${FILES}" | base64 -d | xargs -0 -r -L 1
      [ -n "${FILES}" ] || break
    done
    IFS="${OLDIFS}"
  fi
  #printf -- '##\n'
  ## Show wanted output of remaining package info files that contain these search values
  ## ATTENTION! Additional lines can be selected by initializing ALLMATCHSETS with these
  if [ -n "${FILES}" -a -n "${MUST_MATCH_OUTPUT}${EXTRA_OUTPUT_MATCH}" ]
   then
    [ -z "${ALLMATCHSETS}" ] || printf -- '## >>> %s:\n' "${ALLMATCHSETS}"
    #
    MATCHSET="$(printf -- '%s\\n%s' "${MUST_MATCH_OUTPUT}" "${EXTRA_OUTPUT_MATCH}" | sed -e 's#\\n#\\t#g')"
    IFS="${TABIFS}"
    #set -x
    MATCHSETX="$(printf -- "${MATCHSET}")"
    #
    if [ "${UNIQUE:-0}" -eq 1 ]  ## unique values
     then
      printf -- "${FILES}" | base64 -d | xargs -0 -r -L 10 -- grep -R -h ${MATCHSETX} -- | sort | uniq -c
    else
      printf -- "${FILES}" | base64 -d | xargs -0 -r -L 10 -- grep -R -H ${MATCHSETX} --
    fi
    #set +x
    IFS="${OLDIFS}"
  fi
  printf -- '#\n'
done
