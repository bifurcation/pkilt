#!/usr/bin/ruby
require 'net/http'
require 'uri'
require 'csv'
require 'json'
require 'base64'
require 'openssl'
require 'pp'

# Get the IncludedCA list from Mozilla so we can match
# to the bucket numbers
included_uri = URI('https://mozillacaprogram.secure.force.com/CA/IncludedCACertificateReportPEMCSV')
included_csv = Net::HTTP.get(included_uri).force_encoding("UTF-8")
included_p = CSV.parse(included_csv, headers: :first_row )

included = {}
included_p.each do |row|
  # Convert to a more usable representation
  k = row["SHA-256 Fingerprint"].delete(':').downcase
  begin
    b64 = row["PEM Info"].split(/\n/).reject{|l| l =~ /\A----/}.join("")
    der = Base64.decode64(b64)
    cert = OpenSSL::X509::Certificate.new(c)
    # Prefer CommonName for the name, fall back to
    # OrganizationalUnit if no CommonNames are in cert
    subjattrs = cert.subject.to_a
    a = subjattrs.select {|attr| attr[0] == "CN"}
    if a.empty?
      a = subjattrs.select {|attr| attr[0] == "OU"}
    end
    row["friendly"] = a.first[1].force_encoding("UTF-8")
  rescue
    row["friendly"] = row["Common Name or Certificate Name"]
  end
  included[k] = row
end

krh_uri = URI('https://hg.mozilla.org/mozilla-central/raw-file/tip/security/manager/tools/KnownRootHashes.json')
krh_json = Net::HTTP.get(krh_uri)
krh = JSON.parse(krh_json)

# Update roots data with full Unicode names and Owners
krh["roots"] = krh["roots"].map do |r|
  sha256hex = Base64.decode64(r["sha256Fingerprint"]).unpack('H*').first
  if included.has_key?(sha256hex)
    r["label"] = included[sha256hex]["friendly"]
    # A few Owner entries have the form "Owner / Brand", we just want the owner
    r["owner"] = included[sha256hex]["Owner"].split(" / ").first
  else
    r["owner"] = "<unknown>"
  end
  r
end

puts "// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//
//***************************************************************************
// This is an automatically generated file.
// You should never need to manually edit it.
//***************************************************************************

"

print "var knownRootHashes = "
puts JSON.pretty_generate(krh)
