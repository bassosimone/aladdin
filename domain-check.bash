#!/bin/bash
#
# aladdin: a diamond in the rough next-gen web connectivity
#
# This is an experiment to explore how specific subsets of the next
# generation web connectivity nettest would look like.
#
# The probe-engine/miniooni platform already contains enough functionality
# to allow us to implement most of the rest as a bash script for now.
#
# Of course, the final objective is to get this right and rewrite all
# this in golang, to be integrated in probe-engine.
#
# This work has been heavily influenced by Jigsaw-Code/net-analysis
# blocktest/measure.sh methodology <https://git.io/JfsZb>.
#

function usage_then_die() {
  echo ""
  echo "usage: $0 <domain>" 1>&2
  echo ""
  echo "# Environment variables"
  echo ""
  echo "- MINIOONI_TEST_HELPER: optional domain for test helper"
  echo ""
  echo "- MINIOONI_EXTRA_OPTIONS: extra options for miniooni (e.g. -n to avoid"
  echo "submitting measurements to the OONI collector)"
  echo ""
  exit 1
}

acceptance_file=I_UNDERSTAND_THE_RISK

function disclaimer_then_die() {
  cat << EOF
======= BEGIN DISCLAIMER =======

github.com/bassosimone/aladdin contains experimental OONI code for performing
network measurements. Because this is experimental code, we cannot guarantee the
same level of vetting of non-experimental OONI code. On top of that, the logic
that generates yes/no/maybe results in this script is alpha stage code.

This repository will upload measurements to the OONI collector. You should read
OONI's data policy <https://ooni.org/about/data-policy> as well as the docs on
potential risks <https://ooni.org/about/risks/>.

If you understand (1) the above disclaimer about experimental code, (2) the
data policy, (3) and the risks document, and want to run aladdin, then please
create an empty file named $acceptance_file in the current directory.

======= END DISCLAIMER =======
EOF
  exit 1
}

inputCount=$#

[ $inputCount -ge 1 ] || usage_then_die
[ -f $acceptance_file ] || disclaimer_then_die

function log() {
  echo "$@" 1>&2
}

function checking() {
  log -n "checking $@... "
}

function fatal() {
  log "$@"
  exit 1
}

function require() {
  checking "for $1"
  if ! [ -x "$(command -v $1)" ]; then
    fatal "not found; please run: $2"
  fi
  log "ok"
}

require base64 "sudo apt install coreutils (or sudo apk add coreutils)"
require gcc "sudo apt install gcc (or sudo apk add gcc)"
require git "sudo apt install git (or sudo apk add git)"
require go "sudo apt install golang (or sudo apk add go)"
require jq "sudo apt install jq (or sudo apk add jq)"
require openssl "sudo apt install openssl (or sudo apk add openssl)"
require uuidgen "sudo apt install uuid-runtime (or sudo apk add util-linux)"

measurement_path=`date +%Y%m%dT%H%M%SZ`-`basename $1`
mkdir -p ./tmp/"$measurement_path"
log_file=./tmp/"$measurement_path"/aladdin.log

function run() {
  echo ""      >> $log_file
  echo "+ $@"  >> $log_file
  "$@"        2>> $log_file
}

report_file=./tmp/"$measurement_path"/report.jsonl

function fatal_with_logs() {
  log "$@"
  log "please, check $log_file and $report_file for more insights"
  exit 1
}

function must() {
  "$@" || fatal_with_logs "failure"
}

log -n "building the latest version of miniooni (may take long time!)... "
must run go build -tags nomk ./cmd/aladdin
log "done"

doh_cache="-ODNSCache=dns.google 8.8.8.8 8.8.4.4"
doh_url="-OResolverURL=doh://google"
log "options used to enable alternative resolver: \"$doh_cache\" $doh_url"

checking "for test helper to use"
test_helper=${MINIOONI_TEST_HELPER:-example.org}
log "$test_helper"

checking "for extra options to pass to miniooni"
extra_options=${MINIOONI_EXTRA_OPTIONS}
log "$extra_options"

function urlgetter() {
  run ./aladdin -v $extra_options -o $report_file -Asession=$uuid "$@" urlgetter
}

function getipv4first() {
  tail -n1 $report_file|jq -r ".test_keys.queries|.[]|select(.hostname==\"$1\")|select(.query_type==\"A\")|.answers|.[0].ipv4"
}

log -n "getting $test_helper's IP address using alternative resolver... "
urlgetter -Astep=resolve_test_helper_ip \
          "$doh_cache" \
          $doh_url \
          -idnslookup://$test_helper
test_helper_ip=$(getipv4first $test_helper)
{ [ "$test_helper_ip" != "" ] && log "$test_helper_ip"; } || fatal_with_logs "failure"

function getfailure() {
  tail -n1 $report_file|jq -r .test_keys.failure
}

function maybe() {
  log "maybe (check $report_file)"
}

function getipv4list() {
  echo $(tail -n1 $report_file|jq -r ".test_keys.queries|.[]|select(.hostname==\"$1\")|select(.query_type==\"A\")|.answers|.[].ipv4"|sort)
}

function getcertificatefile() {
  local filename=$(mktemp ./tmp/"$measurement_path"/aladdin.XXXXXX)
  tail -n1 report.jsonl|jq -r '.test_keys.tls_handshakes|.[]|.peer_certificates|.[0]|.data'|base64 -d > $filename
  echo $filename
}

function printcertificate() {
  local certfile
  certfile=$(getcertificatefile)
  checking "for x509 certificate issuer"
  log $(openssl x509 -inform der -in $certfile -noout -issuer 2>/dev/null|head -n1|sed 's/^issuer=\ *//g')
  checking "for x509 certificate subject"
  log $(openssl x509 -inform der -in $certfile -noout -subject 2>/dev/null|head -n1|sed 's/^subject=\ *//g')
  checking "for x509 certificate notBefore"
  log $(openssl x509 -inform der -in $certfile -noout -dates 2>/dev/null|head -n1|sed 's/^notBefore=//g')
  checking "for x509 certificate notAfter"
  log $(openssl x509 -inform der -in $certfile -noout -dates 2>/dev/null|sed -n 2p|sed 's/^notAfter=//g')
  checking "for x509 certificate SHA1 fingerprint"
  log $(openssl x509 -inform der -in $certfile -noout -fingerprint 2>/dev/null|head -n1|sed 's/^SHA1 Fingerprint=//g')
}

function getbodyfile() {
  # Implementation note: requests stored in LIFO order
  local filename=$(mktemp ./tmp/"$measurement_path"/aladdin.XXXXXX)
  tail -n1 $report_file|jq -r ".test_keys.requests|.[0]|.response.body" > $filename
  echo $filename
}

function diffbodyfile() {
  local filename=$(mktemp ./tmp/"$measurement_path"/aladdin.XXXXXX)
  diff -u $1 $2 > $filename
  echo $filename
}

function main() {
  domain=$1

  log -n "generating UUID to correlate measurements... "
  uuid=$(uuidgen)
  log "$uuid"

  checking "for SNI-triggered blocking"
  urlgetter -Astep=sni_blocking \
            -OTLSServerName=$domain \
            -itlshandshake://$test_helper_ip:443
  { [ "$(getfailure)" = "ssl_invalid_hostname" ] && log "no"; } || maybe

  checking "for host-header-triggered blocking"
  urlgetter -Astep=host_header_blocking \
            -OHTTPHost=$domain \
            -ONoFollowRedirects=true \
            -ihttp://$test_helper_ip
  { [ "$(getfailure)" = "null" ] && log "no"; } || maybe

  checking "for DNS injection"
  urlgetter -Astep=dns_injection \
            -OResolverURL=udp://$test_helper_ip:53 \
            -idnslookup://$domain
  { [ "$(getfailure)" = "null" ] && log "yes"; } || log "no"

  checking "whether the system resolver returns bogons"
  urlgetter -Astep=bogons \
            -ORejectDNSBogons=true \
            -idnslookup://$domain
  { [ "$(getfailure)" = "dns_bogon_error" ] && log "yes"; } || log "no"

  checking "for IPv4 addresses returned by the system resolver"
  # Implementation note: with dns_bogons_error we still have the IP addresses
  # available inside the response, so we can read then
  ipv4_system_list=$(mktemp ./tmp/"$measurement_path"/aladdin.XXXXXX)
  getipv4list $domain > $ipv4_system_list
  log $(cat $ipv4_system_list)

  checking "for IPv4 addresses returned by the alternate resolver"
  urlgetter -Astep=doh_lookup \
            "$doh_cache" \
            $doh_url \
            -idnslookup://$domain
  ipv4_doh_list=$(mktemp ./tmp/"$measurement_path"/aladdin.XXXXXX)
  getipv4list $domain > $ipv4_doh_list
  log $(cat $ipv4_doh_list)

  checking "for DNS consistency between system and alternate resolver"
  ipv4_overlap_list=$(comm -12 $ipv4_system_list $ipv4_doh_list)
  { [ "$ipv4_overlap_list" != "" ] && log "yes"; } || log "no"

  checking "whether the system resolver lied to us"
  urlgetter -Astep=system_resolver_validation \
            "-ODNSCache=$domain $(cat $ipv4_system_list)" \
            -ihttps://$domain/
  vanilla_failure=$(getfailure)
  { [ "$vanilla_failure" = "null" ] && log "no"; } || maybe
  printcertificate
  body_vanilla=$(getbodyfile)
  log "webpage body available at... $body_vanilla"

  checking "whether we obtain the same body using psiphon"
  urlgetter -Astep=psiphon -OTunnel=psiphon -ihttps://$domain
  body_tunnel=$(getbodyfile)
  body_diff=$(diffbodyfile $body_vanilla $body_tunnel)
  { [ "$(cat $body_diff)" = "" ] && log "yes"; } || log "no (see $body_diff)"

  checking "whether we can retrieve a webpage by removing TLS validation"
  urlgetter -Astep=https_blockpage_fetch \
            "-ODNSCache=$domain $(cat $ipv4_system_list)" \
            -ONoTLSVerify=true \
            -ihttps://$domain/
  { [ "$(getfailure)" = "null" ] && log "yes"; } || log "no"
  printcertificate
  body_noverify=$(getbodyfile)
  log "webpage body available at... $body_noverify"
  checking "whether we obtain the same body using psiphon"
  body_diff=$(diffbodyfile $body_noverify $body_tunnel)
  { [ "$(cat $body_diff)" = "" ] && log "yes"; } || log "no (see $body_diff)"

  checking "whether we can retrieve a webpage using the alternate resolver"
  urlgetter -Astep=doh_resolver_validation \
            "-ODNSCache=$domain $(cat $ipv4_doh_list)" \
            -ihttps://$domain/
  { [ "$(getfailure)" = "null" ] && log "yes"; } || log "no"
  printcertificate
  body_doh=$(getbodyfile)
  log "webpage body available at... $body_doh"
  checking "whether we obtain the same body using psiphon"
  body_diff=$(diffbodyfile $body_doh $body_tunnel)
  { [ "$(cat $body_diff)" = "" ] && log "yes"; } || log "no (see $body_diff)"
}

inputCounter=0
while [[ $1 != "" ]]; do
  ((inputCounter++))
  log "[$inputCounter/$inputCount] running with input: $1"
  main $1 &
  wait
  sleep 1
  shift
done
