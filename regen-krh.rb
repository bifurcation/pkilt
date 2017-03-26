#!/usr/bin/ruby
require 'net/http'
require 'uri'
require 'csv'
require 'json'
require 'base64'
require 'openssl'
require 'pp'

included_uri = URI('https://mozillacaprogram.secure.force.com/CA/IncludedCACertificateReportPEMCSV')
included_csv = Net::HTTP.get(included_uri).force_encoding("UTF-8")
included_p = CSV.parse(included_csv, headers: :first_row )

included = {}
included_p.each do |row|
  k = row["SHA-256 Fingerprint"].delete(':').downcase
  begin
    b64 = row["PEM Info"].split(/\n/).reject{|l| l =~ /\A----/}.join("")
    der = Base64.decode64(b64)
    cert = OpenSSL::X509::Certificate.new(c)
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

roots = krh["roots"].map do |r|
  sha256hex = Base64.decode64(r["sha256Fingerprint"]).unpack('H*').first
  if included.has_key?(sha256hex)
    r["label"] = included[sha256hex]["friendly"]
    r["owner"] = included[sha256hex]["Owner"]
  else
    r["owner"] = "<unknown>"
  end
  r
end

krh["roots"] = roots

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
