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
same level of vetting of non-experimental OONI code. In particular, the logic
that generate yes/no results in this script is still experimental/alpha.

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

[ $# -eq 1 ] || usage_then_die
[ -f $acceptance_file ] || disclaimer_then_die

domain=$1

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

log_file=miniooni.log
log -n "removing stale $log_file from previous runs if needed... "
rm -f $log_file
log "done"

function run() {
  echo ""      >> $log_file
  echo "+ $@"  >> $log_file
  "$@"        2>> $log_file
}

report_file=report.jsonl

function fatal_with_logs() {
  log "$@"
  log "please, check $log_file and $report_file for more insights"
  exit 1
}

function must() {
  "$@" || fatal_with_logs "failure"
}

log -n "building the latest version of miniooni... "
must run go build -tags nomk github.com/ooni/probe-engine/cmd/miniooni
log "done"

log -n "generating UUID to correlate measurements... "
uuid=$(uuidgen)
log "$uuid"

checking "for what test helper to use"
test_helper=${MINIOONI_TEST_HELPER:-example.org}
log "$test_helper"

checking "for extra options to pass to miniooni"
extra_options=${MINIOONI_EXTRA_OPTIONS}
log "$extra_options"

function urlgetter() {
  run ./miniooni -v $extra_options -A session=$uuid "$@" urlgetter
}

function getipv4first() {
  tail -n1 $report_file|jq -r ".test_keys.queries|.[]|select(.hostname==\"$1\")|select(.query_type==\"A\")|.answers|.[0].ipv4"
}

doh_cache="-ODNSCache=8.8.4.4 dns.google"
doh_url="-OResolverURL=doh://google"

log -n "getting $test_helper's IP address... "
urlgetter "$doh_cache" $doh_url -i dnslookup://$test_helper
test_helper_ip=$(getipv4first $test_helper)
{ [ "$test_helper_ip" != "" ] && log "$test_helper_ip"; } || fatal_with_logs "failure"

function getfailure() {
  tail -n1 $report_file|jq -r .test_keys.failure
}

checking "for sni-triggered blocking"
urlgetter -OTLSServerName=$domain -i tlshandshake://$test_helper_ip:443
{ [ "$(getfailure)" = "ssl_invalid_hostname" ] && log "no"; } || log "yes"

checking "for host-header-triggered blocking"
urlgetter -OHTTPHost=$domain -ONoFollowRedirects=true -i http://$test_helper_ip
{ [ "$(getfailure)" = "null" ] && log "no"; } || log "yes"

checking "for DNS injection"
urlgetter -OResolverURL=udp://$test_helper_ip:53 -i dnslookup://$domain
{ [ "$(getfailure)" = "null" ] && log "yes"; } || log "no"

checking "whether the system resolver returns bogons"
urlgetter -ORejectDNSBogons=true -i dnslookup://$domain
{ [ "$(getfailure)" = "dns_bogon_error" ] && log "yes"; } || log "no"

function getipv4list() {
  tail -n1 $report_file|jq -r ".test_keys.queries|.[]|select(.hostname==\"$1\")|select(.query_type==\"A\")|.answers|.[].ipv4"|sort
}

checking "for IPv4 addresses returned by the system resolver"
urlgetter -i dnslookup://$domain
ipv4_system_list=$(mktemp ./aladdin.XXXXXX)
getipv4list $domain > $ipv4_system_list
log $(cat $ipv4_system_list)

checking "for IPv4 addresses returned by DoH"
urlgetter "$doh_cache" $doh_url -i dnslookup://$domain
ipv4_doh_list=$(mktemp ./aladdin.XXXXXX)
getipv4list $domain > $ipv4_doh_list
log $(cat $ipv4_doh_list)

checking "for DNS consistency"
ipv4_overlap_list=$(comm -12 $ipv4_system_list $ipv4_doh_list)
{ [ "$ipv4_overlap_list" != "" ] && log "yes"; } || log "no"

for ip in $(cat $ipv4_system_list); do
  checking "whether $ip is valid for $domain"
  urlgetter -OTLSServerName=$domain -i tlshandshake://$ip:443
  { [ "$(getfailure)" = "null" ] && log "yes"; } || log "no"
done

function getcertificatefile() {
  local filename=$(mktemp ./aladdin.XXXXXX)
  tail -n1 report.jsonl|jq -r '.test_keys.tls_handshakes|.[]|.peer_certificates|.[0]|.data'|base64 --decode > $filename
  echo $filename
}

checking "for HTTPS certificate issuer"
urlgetter -ONoTLSVerify=true -OTLSServerName=$domain -i tlshandshake://$ip:443
certfile=$(getcertificatefile)
log $(openssl x509 -inform der -in $certfile -issuer|head -n1|sed 's/^issuer= //g')

checking "for HTTPS certificate subject"
log $(openssl x509 -inform der -in $certfile -subject|head -n1|sed 's/^subject= //g')

checking "for HTTPS certificate notBefore"
log $(openssl x509 -inform der -in $certfile -dates|head -n1|sed 's/^notBefore=//g')

checking "for HTTPS certificate notAfter"
log $(openssl x509 -inform der -in $certfile -dates|sed -n 2p|sed 's/^notAfter=//g')

checking "for HTTPS certificate SHA1 fingerprint"
log $(openssl x509 -inform der -in $certfile -fingerprint|head -n1|sed 's/^SHA1 Fingerprint=//g')

function getbodyfile() {
  # Implementation note: requests stored in LIFO order
  local filename=$(mktemp ./aladdin.XXXXXX)
  tail -n1 $report_file|jq -r ".test_keys.requests|.[0]|.response.body" > $filename
  echo $filename
}

function diffbodyfile() {
  local filename=$(mktemp ./aladdin.XXXXXX)
  diff -u $1 $2 > $filename
  echo $filename
}

checking "for HTTP body consistency"
urlgetter -i http://$domain
body_vanilla=$(getbodyfile)
urlgetter -OTunnel=psiphon -i http://$domain
body_tunnel=$(getbodyfile)
body_diff=$(diffbodyfile $body_vanilla $body_tunnel)
{ [ "$(cat $body_diff)" = "" ] && log "yes"; } || log "no (see $body_diff)"

checking "for HTTPS body consistency"
urlgetter -i https://$domain
body_vanilla=$(getbodyfile)
urlgetter -OTunnel=psiphon -i https://$domain
body_tunnel=$(getbodyfile)
body_diff=$(diffbodyfile $body_vanilla $body_tunnel)
{ [ "$(cat $body_diff)" = "" ] && log "yes"; } || log "no (see $body_diff)"
