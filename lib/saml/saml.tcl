#! /usr/bin/tclsh

package require tax 0.2
package require pki 0.6
package require sha256
package require sha1

namespace eval ::saml {}
namespace eval ::saml::xml_c14n {}
namespace eval ::saml::xml_req {}
namespace eval ::saml::xml_response {}

proc ::saml::_generate_random {bytes} {
	set data ""
	while {[string length $data] < $bytes} {
		append data [::pki::_random -binary]
	}

	set data [string range $data 0 [expr {$bytes - 1}]]

	binary scan $data H* data

	return $data
}

proc ::saml::_sha256 {data} {
	set data [sha2::sha256 -bin $data]
	set data [binary encode base64 $data]
	return $data
}

proc ::saml::_sha1 {data} {
	set data [sha1::sha1 -bin $data]
	set data [binary encode base64 $data]
	return $data
}

proc ::saml::sign {key data} {
	set data [::pki::sign $data $key sha1]
	set data [binary encode base64 $data]
	return $data
}

proc ::saml::verify {cert signature plaintext} {
	set data [binary decode base64 $signature]

	set retval [::pki::verify $data $plaintext $cert]

	return $retval
}

proc ::saml::xml_c14n::cb {tag close selfclose attrslist body} {
	if {$tag == "docstart"} {
		return
	}

	set skip 0

	foreach skip_ele $::saml::xml_c14n::skiplist {
		if {[lsearch -exact $::saml::xml_c14n::stack $skip_ele] != -1} {
			set skip 1
		}

		if {$tag == $skip_ele} {
			set skip 1
		}
	}

	if {$::saml::xml_c14n::startele != ""} {
		if {[lsearch -exact $::saml::xml_c14n::stack $::saml::xml_c14n::startele] == -1 && $tag != $::saml::xml_c14n::startele} {
			set skip 1
		}
	}

	if {$close} {
		if {!$skip} {
			append ::saml::xml_c14n::buf "</$tag>"
		}

		set ::saml::xml_c14n::stack [lrange $::saml::xml_c14n::stack 0 end-1]

		return
	}

	lappend ::saml::xml_c14n::stack $tag

	set attrstr ""
	foreach {attr val} $attrslist {
		append attrstr " $attr=\"$val\""
	}

	if {!$skip} {
		append ::saml::xml_c14n::buf "<$tag$attrstr>[string trim $body]"
	}

	if {$selfclose} {
		if {!$skip} {
			append ::saml::xml_c14n::buf "</$tag>"
		}

		set ::saml::xml_c14n::stack [lrange $::saml::xml_c14n::stack 0 end-1]
	}
}

proc ::saml::xml_c14n::c14n {xml {skiplist ""} {startele ""}} {
	set ::saml::xml_c14n::stack [list]
	set ::saml::xml_c14n::buf ""
	set ::saml::xml_c14n::skiplist $skiplist
	set ::saml::xml_c14n::startele $startele

	::tax::parse ::saml::xml_c14n::cb $xml

	return $::saml::xml_c14n::buf
}

proc ::saml::xml_req::cb {tag close selfclose attrslist body} {
	if {$tag == "docstart"} {
		return
	}

	if {$close} {
		set ::saml::xml_req::stack [lrange $::saml::xml_req::stack 0 end-1]

		return
	}

	regsub {^.*:} $tag {} short_tag
	lappend ::saml::xml_req::stack $short_tag

	array set attrs $attrslist

	set location [join $::saml::xml_req::stack .]

	switch -- $location {
		{AuthnRequest} {
			if {[info exists attrs(AssertionConsumerServiceURL)]} {
				set ::saml::xml_req::ret(spurl) $attrs(AssertionConsumerServiceURL)
			}
			if {[info exists attrs(Destination)]} {
				set ::saml::xml_req::ret(idpurl) $attrs(Destination)
			}
			if {[info exists attrs(ID)]} {
				set ::saml::xml_req::ret(id) $attrs(ID)
			}
		}
		{AuthnRequest.Issuer} {
			set ::saml::xml_req::ret(issuer) [string trim $body]
		}
	}

	if {$selfclose} {
		set ::saml::xml_req::stack [lrange $::saml::xml_req::stack 0 end-1]
	}
}

proc ::saml::xml_req::parse {xml} {
	set ::saml::xml_req::stack [list]
	unset -nocomplain ::saml::xml_req::ret

	array set ::saml::xml_req::ret [list]

	tax::parse ::saml::xml_req::cb $xml

	foreach {var val} [array get ::saml::xml_req::ret] {
		if {[string match {*[<"'">]*} $val]} {
			continue
		}

		if {[string match "*@|@*" $val]} {
			continue
		}

		lappend ret $var $val
	}

	return $ret
}

proc ::saml::xml_response::cb {tag close selfclose attrslist body} {
	if {$tag == "docstart"} {
		return
	}

	if {$close} {
		set ::saml::xml_response::stack [lrange $::saml::xml_response::stack 0 end-1]

		return
	}

	regsub {^.*:} $tag {} short_tag
	lappend ::saml::xml_response::stack $short_tag

	array set attrs $attrslist

	set location [join $::saml::xml_response::stack .]

	switch -- $location {
		{Response.Status.StatusCode} {
			if {[info exists attrs(Value)]} {
				set ::saml::xml_response::ret(status) $attrs(Value)
			}
		}
		{Response.Assertion.Subject.NameID} {
			if {[info exists attrs(Format)]} {
				set ::saml::xml_response::ret(uid-format) $attrs(Format)
			}
			set ::saml::xml_response::ret(uid) $body
		}
		{Response.Assertion.Signature.SignedInfo.Reference.DigestMethod} {
			set ::saml::xml_response::ret(digest-method) $attrs(Algorithm)
		}
		{Response.Assertion.Signature.SignedInfo.Reference.DigestValue} {
			set ::saml::xml_response::ret(digest) $body
		}
		{Response.Assertion.Signature.SignatureValue} {
			set ::saml::xml_response::ret(signature) $body
		}
		{Response.Assertion.Signature.KeyInfo.X509Data.X509Certificate} {
			set ::saml::xml_response::ret(certificate) $body
		}
		{Response.Assertion.Conditions} {
			set ::saml::xml_response::ret(conditions) [array get attrs]
		}
	}

	if {$selfclose} {
		set ::saml::xml_response::stack [lrange $::saml::xml_response::stack 0 end-1]
	}
}

proc ::saml::xml_response::parse {xml} {
	regsub -all {^<\?.*\?>} $xml {} xml
	set ::saml::xml_response::stack [list]
	unset -nocomplain ::saml::xml_response::ret

	array set ::saml::xml_response::ret [list]

	tax::parse ::saml::xml_response::cb $xml

	foreach {var val} [array get ::saml::xml_response::ret] {
		if {[string match {*[<"'">]*} $val]} {
			continue
		}

		if {[string match "*@|@*" $val]} {
			continue
		}

		lappend ret $var $val
	}

	return $ret
}

proc ::saml::gen_request {issuer} {
	set id [::saml::_generate_random 20]
	set now [clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S}]

	set request "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"$id\" Version=\"2.0\" IssueInstant=\"$now\" AssertionConsumerServiceIndex=\"0\" AttributeConsumingServiceIndex=\"0\" AssertionConsumerServiceURL=\"$issuer\">"
	append request "\t<saml:Issuer>$issuer</saml:Issuer>"
	append request "\t<samlp:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"/>"
	append request "</samlp:AuthnRequest>"
}

proc ::saml::verify_signature {response_arr response_xml certificate} {
	regsub -all {^<\?.*\?>} $response_xml {} response_xml
	array set response $response_arr

	# Compute digest (XXX: TODO: Support other methods, like SHA256)
	set digest_of [::saml::xml_c14n::c14n $response_xml [list "ds:Signature"] "Assertion"]
	set digest [::saml::_sha1 $digest_of]

	if {$digest != $response(digest)} {
		return false
	}

        # Compute signature
	set user_certificate [pki::x509::parse_cert [binary decode base64 $response(certificate)]]
        set signature_of [::saml::xml_c14n::c14n $response_xml [list] "ds:SignedInfo"]
        set valid_signature [::saml::verify $user_certificate $response(signature) $signature_of]
	if {!$valid_signature} {
		return false
	}

	# Verify certificate was one used
	array set certificate_array [pki::x509::parse_cert $certificate]
	array set user_certificate_array $user_certificate
	if {$certificate_array(n) != $user_certificate_array(n)} {
		return false
	}

	return true
}

proc ::saml::response {response_xml cert} {
	array set response [::saml::xml_response::parse $response_xml]

	set valid [::saml::verify_signature [array get response] $response_xml $cert]
	if {!$valid} {
		return [list status FAILED status_reason invalid_signature]
	}

	array set retval [list]

	switch -- $response(status) {
		{urn:oasis:names:tc:SAML:2.0:status:Success} {
			set retval(status) OK
		}
		default {
			return [list status FAILED status_reason response_status_invalid]
		}
	}

	set now [clock seconds]
	foreach {condition value} $response(conditions) {
		switch -- $condition {
			NotBefore {
				set value [clock scan $value -format {%Y-%m-%dT%H:%M:%S%Z}]
				if {$now < $value} {
					return [list status FAILED status_reason condition_$condition]
				}
			}
			NotOnOrAfter {
				set value [clock scan $value -format {%Y-%m-%dT%H:%M:%S%Z}]
				if {$now >= $value} {
					return [list status FAILED status_reason condition_$condition]
				}
			}
			default {
				return [list status FAILED status_reason condition_$condition]
			}
		}
	}

	if {[info exists response(uid)]} {
		set retval(uid) $response(uid)
	}

	return [array get retval]
}

proc ::saml::request {key cert id data username {spurl ""}} {
	if {$data != ""} {
		array set reqinfo [::saml::xml_req::parse $data]
	} else {
		set reqinfo(spurl) $spurl
	}

	set key [::pki::pkcs::parse_key $key]

	set response {<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
    Destination="@|@DESTINATION@|@"
    ID="_@|@RESID@|@"
    InResponseTo="@|@REQID@|@"
    IssueInstant="@|@CURRENTTIME@|@"
    Version="2.0"
    xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:protocol http://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd">
	<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		@|@ISSUERID@|@
	</saml:Issuer>
	<samlp:Status>
		<samlp:StatusCode
		    Value="urn:oasis:names:tc:SAML:2.0:status:Success">
		</samlp:StatusCode>
	</samlp:Status>
	<Assertion
	    xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
	    ID="_@|@ASSERTID@|@"
	    IssueInstant="@|@CURRENTTIME@|@"
	    Version="2.0">
		<Issuer>
			@|@ISSUERID@|@
		</Issuer>
		<ds:Signature
		    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<ds:CanonicalizationMethod
				    Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				<ds:SignatureMethod
				    Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
				<ds:Reference
				    URI="#_@|@ASSERTID@|@">
					<ds:Transforms>
						<ds:Transform
						    Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
						<ds:Transform
						    Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
					</ds:Transforms>
					<ds:DigestMethod
					    Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
					<ds:DigestValue>@|@DIGEST@|@</ds:DigestValue>
				</ds:Reference>
			</ds:SignedInfo>
			<ds:SignatureValue>@|@SIGNATURE@|@</ds:SignatureValue>
			<KeyInfo
			    xmlns="http://www.w3.org/2000/09/xmldsig#">
				<ds:X509Data>
					<ds:X509Certificate>@|@CERTIFICATE@|@</ds:X509Certificate>
				</ds:X509Data>
			</KeyInfo>
		</ds:Signature>
		<Subject>
			<NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
				@|@USERNAME@|@
			</NameID>
			<SubjectConfirmation
			    Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
				<SubjectConfirmationData
				    InResponseTo="@|@REQID@|@"
				    NotOnOrAfter="@|@EXPIRETIME@|@"
				    Recipient="@|@DESTINATION@|@"/>
			</SubjectConfirmation>
		</Subject>
		<Conditions NotBefore="@|@VALIDBEGINTIME@|@" NotOnOrAfter="@|@EXPIRETIME@|@">
			<AudienceRestriction>
				<Audience>
					@|@REQISSUERID@|@
				</Audience>
			</AudienceRestriction>
		</Conditions>
		<AttributeStatement>
			<Attribute
			    Name="uid">
				<AttributeValue>@|@USERNAME@|@</AttributeValue>
			</Attribute>
		</AttributeStatement>
		<AuthnStatement
		    AuthnInstant="@|@CURRENTTIME@|@"
		    SessionIndex="_@|@ASSERTID@|@">
			<AuthnContext>
				<AuthnContextClassRef>
					urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
				</AuthnContextClassRef>
			</AuthnContext>
		</AuthnStatement>
	</Assertion>
</samlp:Response>}

	# Compute Parameters
	## Certificate
	array set certarray [::pki::_parse_pem $cert "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"]
	set cert [binary encode base64 $certarray(data)]
	set response_map(@|@CERTIFICATE@|@) $cert

	## Permenant Identifiers
	### Destination URL (Service Provider, from request)
	if {[info exists reqinfo(spurl)]} {
		set response_map(@|@DESTINATION@|@) $reqinfo(spurl)
	}

	### Destination ID (from request)
	if {[info exists reqinfo(issuer)]} {
		set response_map(@|@REQISSUERID@|@) $reqinfo(issuer)
	}

	### Issuer (Identity Provider)
	set response_map(@|@ISSUERID@|@) $id

	## Temporary Identifiers
	### Session Identifier (from request)
	if {[info exists reqinfo(id)]} {
		set response_map(@|@REQID@|@) $reqinfo(id)
	}

	### Response Identifier
	set response_map(@|@RESID@|@) [::saml::_generate_random 20]

	### Assertion Identifier
	set response_map(@|@ASSERTID@|@) [::saml::_generate_random 20]

	## Times
	### Current time
	set response_map(@|@CURRENTTIME@|@) [clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%SZ} -timezone :UTC]

	## Not before (a few minutes in the past to deal with clock sync issues)
	set response_map(@|@VALIDBEGINTIME@|@) [clock format [clock add [clock seconds] -5 minutes] -format {%Y-%m-%dT%H:%M:%SZ} -timezone :UTC]

	### Expiration of token (30 minutes)
	set response_map(@|@EXPIRETIME@|@) [clock format [clock add [clock seconds] 30 minutes] -format {%Y-%m-%dT%H:%M:%SZ} -timezone :UTC]

	## Username
	set response_map(@|@USERNAME@|@) $username

	# Insert Parameters
	set response [string map [array get response_map] $response]

	# Remove lines that contain unsubstituted values
	set new_response [list]
	foreach line [split $response "\n"] {
		if {[string match "*@|@*" $line]} {
			if {![string match "*@|@DIGEST@|@*" $line] && ![string match "*@|@SIGNATURE@|@*" $line]} {
				continue
			}
		}

		lappend new_response $line
	}
	set response [join $new_response "\n"]

	# Compute digest
	set digest_of [::saml::xml_c14n::c14n $response [list "ds:Signature"] "Assertion"] 
	set response_digest [::saml::_sha1 $digest_of]
	set response [string map [list @|@DIGEST@|@ $response_digest] $response]

	# Compute signature
	set signature_of [::saml::xml_c14n::c14n $response [list] "ds:SignedInfo"]
	set response_signature [::saml::sign $key $signature_of]
	set response [string map [list @|@SIGNATURE@|@ $response_signature] $response]

	# Emit response
	return [list spurl $reqinfo(spurl) response [encoding convertto utf-8 "<?xml version=\"1.0\" encoding=\"utf-8\"?>[::saml::xml_c14n::c14n $response]"]]
}

proc ::saml::idp_metadata {cert providerid location} {
	set response {<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="@@ID@@" cacheDuration="PT1440M" entityID="@@PROVIDERID@@" xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:metadata http://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd">
	<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:KeyDescriptor use="signing">
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<ds:X509Data>
					<ds:X509Certificate>@@CERTIFICATE@@</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</md:KeyDescriptor>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="@@LOCATION@@"/>
	</md:IDPSSODescriptor>
</md:EntityDescriptor>}

	# Compute Parameters
	## Certificate
	array set certarray [::pki::_parse_pem $cert "-----BEGIN CERTIFICATE-----" "-----END CERTIFICATE-----"]
	set cert [binary encode base64 $certarray(data)]
	set response_map(@@CERTIFICATE@@) $cert

	## Identity Provider ID
	set response_map(@@PROVIDERID@@) $providerid

	## Location
	set response_map(@@LOCATION@@) $location

	## ID
	set id [sha2::sha256 -hex "$providerid"]
	set response_map(@@ID@@) $id

	## Insert parameters
	set response [string map [array get response_map] $response]

	return $response
}

package provide saml 0.1
