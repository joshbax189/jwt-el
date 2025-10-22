;;; jwt.el --- Interact with JSON Web Tokens -*- lexical-binding: t -*-

;; Author: Josh Bax
;; Maintainer: Josh Bax
;; Version: 0.2.0
;; Package-Requires: ((emacs "29.1"))
;; Homepage: https://github.com/joshbax189/jwt-el
;; Keywords: tools convenience


;; This file is not part of GNU Emacs

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.


;;; Commentary:

;; Never paste your tokens into jwt.io again!
;; Decode and verify JSON Web Tokens in Emacs.
;;
;; Verification is supported for RSA and HMAC signatures, with SHA256, SHA384 and SHA512 hashes.
;;
;; Signing is supported for HMAC only.

;;; Code:

(require 'json)
(require 'cl-lib)
(require 'hmac-def)
(require 'calc-arith)
(require 'rx)

(defgroup jwt-el nil
  "JSON Web Token display and signing."
  :group 'comm)

(defvar jwt--defined-claims-alist
  '(;; registered claim names
    (iss "Issuer" "Identifies principal that issued the JWT.")
    (sub "Subject" "Identifies the subject of the JWT.")
    (aud "Audience" "Identifies the recipients that the JWT is intended for. Each principal intended to process the JWT must identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the aud claim when this claim is present, then the JWT must be rejected.")
    (exp "Expiration Time" "Identifies the expiration time on and after which the JWT must not be accepted for processing. The value must be a NumericDate: either an integer or decimal, representing seconds past 1970-01-01 00:00:00Z.")
    (nbf "Not Before" "Identifies the time on which the JWT will start to be accepted for processing. The value must be a NumericDate.")
    (iat "Issued at" "Identifies the time at which the JWT was issued. The value must be a NumericDate.")
    (jti "JWT ID" "Case-sensitive unique identifier of the token even among different issuers.")
    (roles "Roles")
    (groups "Groups")
    (entitlements "Entitlements")
    ;; header names
    (typ "Token type"	"If present, it must be set to a registered IANA Media Type.")
    (cty "Content type" "If nested signing or encryption is employed, it is recommended to set this to JWT; otherwise, omit this field.")
    (alg "Message authentication code algorithm" "The issuer can freely set an algorithm to verify the signature on the token.")
    (kid "Key ID" "A hint indicating which key the client used to generate the token signature. The server will match this value to a key on file in order to verify that the signature is valid and the token is authentic.")
    (x5c "x.509 Certificate Chain" "A certificate chain in RFC4945 format corresponding to the private key used to generate the token signature. The server will use this information to verify that the signature is valid and the token is authentic.")
    (x5u "x.509 Certificate Chain URL" "A URL where the server can retrieve a certificate chain corresponding to the private key used to generate the token signature. The server will retrieve and use this information to verify that the signature is authentic.")
    (crit "Critical" "A list of headers that must be understood by the server in order to accept the token as valid")
    ;; additional claims from IANA -- see https://www.iana.org/assignments/jwt/jwt.xhtml
    ;; OIDC core
    (azp "Authorized party" "The party to which the ID Token was issued")
    (auth_time "Authentication Time.")
    (at_hash "Access Token hash value")
    (acr "Authentication Context Class Reference")
    (amr "Authentication Methods References")
    (nonce "Value used to associate a Client session with an ID Token (MAY also be used for nonce values in other applications of JWTs)")
    (c_hash "Code hash value")
    (name "Full name")
    (given_name "Given name(s) or first name(s)")
    (family_name "Surname(s) or last name(s)")
    (middle_name "Middle name(s)")
    (nickname "Casual name")
    (preferred_username "Shorthand name by which the End-User wishes to be referred to")
    (profile "Profile page URL")
    (picture "Profile picture URL")
    (website "Web page or blog URL")
    (email "Preferred e-mail address")
    (email_verified "True if the e-mail address has been verified; otherwise false")
    (gender "Gender")
    (birthdate "Birthday")
    (zoneinfo "Time zone")
    (locale "Locale")
    (phone_number "Preferred telephone number")
    (phone_number_verified "True if the phone number has been verified; otherwise false")
    (address "Preferred postal address")
    (updated_at "Time the information was last updated")
    (_claim_names "JSON object whose member names are the Claim Names for the Aggregated and Distributed Claims")
    (_claim_sources "JSON object whose member names are referenced by the member values of the _claim_names member")
    (sub_jwk "Public key used to check the signature of an ID Token")
    ;; OIDC IA
    (verified_claims "This container Claim is composed of the verification evidence related to a certain verification process and the corresponding Claims about the End-User which were verified in this process.")
    (place_of_birth "A structured claim representing the end-user's place of birth.")
    (nationalities "String array representing the end-user's nationalities.")
    (birth_family_name "Family name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the family name(s) later in life for any reason. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.")
    (birth_given_name "Given name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the given name later in life for any reason. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.")
    (birth_middle_name "Middle name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the middle name later in life for any reason. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures middle names are not used.")
    (salutation "End-user's salutation, e.g. \"Mr\"")
    (title "End-user's title, e.g. \"Dr\"")
    (msisdn "End-user's mobile phone number formatted according to ITU-T recommendation")
    (also_known_as "Stage name, religious name or any other type of alias/pseudonym with which a person is known in a specific context besides its legal name.")
    ;; OIDC logout
    (sid "Session ID" "Specified in OpenID Connect Front-Channel Logout")
    ;; OAuth JWT introspection
    (token_introspection "Token introspection response")
    ;; RATS Entity Attestation Token (EAT)
    (eat_nonce "Entity Attestation Token Nonce")
    (ueid "The Universal Entity ID")
    (sueids "Semi-permanent UEIDs")
    (oemid "Hardware OEM ID")
    (hwmodel "Model identifier for hardware")
    (hwversion "Hardware Version Identifier")
    (oemboot "Indicates whether the software booted was OEM authorized")
    (dbgstat "Debug Status" "Indicates status of debug facilities")
    (location "The geographic location")
    (eat_profile "Entity Attestation Token Profile" "Indicates the EAT profile followed")
    (submods "The section containing submodules")
    (uptime "Uptime")
    (bootcount "The number times the entity or submodule has been booted")
    (bootseed "Identifies a boot cycle")
    (dloas "Certifications received as Digital Letters of Approval")
    (swname "The name of the software running in the entity")
    (swversion "The version of software running in the entity")
    (manifests "Manifests describing the software installed on the entity")
    (measurements "Measurements of the software, memory configuration and such on the entity")
    (measres "The results of comparing software measurements to reference values")
    (intuse "Indicates intended use of the EAT")
    ;; stir passport
    (rcd "Rich Call Data Information")
    (rcdi "Rich Call Data Integrity Information")
    (crn "Call Reason")
    ;; RFC7800
    (cnf "Confirmation")
    ;; RFC8055
    (sip_from_tag "SIP From tag header field parameter value")
    (sip_date "SIP Date header field value")
    (sip_callid "SIP Call-Id header field value")
    (sip_cseq_num "SIP CSeq numeric header field parameter value")
    (sip_via_branch "SIP Via branch header field parameter value")
    ;; RFC8225
    (orig "Originating Identity String")
    (dest "Destination Identity String")
    (mky "Media Key Fingerprint String")
    ;; RFC8417
    (events "Security Events")
    (toe "Time of Event")
    (txn "Transaction Identifier")
    ;; RFC8443
    (rph "Resource Priority Header Authorization")
    ;; RFC8485
    (vot "Vector of Trust value")
    (vtm "Vector of Trust trustmark URL")
    (attest "Attestation level as defined in SHAKEN framework")
    (origid "Originating Identifier as defined in SHAKEN framework")
    ;; RFC8693
    (act "Actor")
    (scope "Scope Values")
    (client_id "Client Identifier")
    (may_act "Authorized Actor - the party that is authorized to become the actor")
    ;; RFC8688
    (jcard "jCard data")
    ;; RFC8946
    (div "Diverted Target of a Call")
    (opt "Original PASSporT (in Full Form)")
    ;; RFC9027
    (sph "SIP Priority header field")
    ;; RFC9200
    (exi "Expires in" "Lifetime of the token in seconds from the time the RS first sees it.  Used to implement a weaker from of token expiration for devices that cannot synchronize their internal clocks.")
    (ace_profile "The ACE profile a token is supposed to be used with.")
    (cnonce "Client Nonce" "A nonce previously provided to the AS by the RS via the client.  Used to verify token freshness when the RS cannot synchronize its clock with the AS.")
    ;; RFC9246
    (cdniip "CDNI IP Address")
    (cdniuc "CDNI URI Container")
    (cdniets "CDNI Expiration Time Setting for Signed Token Renewal")
    (cdnistt "CDNI Signed Token Transport Method for Signed Token Renewal")
    (cdnistd "CDNI Signed Token Depth")
    (cdniv "CDNI Claim Set Version")
    (cdnicrit "CDNI Critical Claims Set")
    ;; RFC9321
    (sig_val_claims "Signature Validation Token")
    ;; RFC9396
    (authorization_details "The claim authorization_details contains a JSON array of JSON objects representing the rights of the access token. Each JSON object contains the data to specify the authorization requirements for a certain type of resource.")
    ;; RFC9447
    (atc "Authority Token Challenge")
    ;; RFC9449
    (htm "The HTTP method of the request")
    (htu "The HTTP URI of the request (without query and fragment parts)")
    (ath "The base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value")
    ;; RFC9475
    (msgi "Message Integrity Information")
    ;; RFC9493
    (sub_id "Subject Identifier")
    ;; RFC9560
    (rdap_allowed_purposes "This claim describes the set of RDAP query purposes that are available to an identity that is presented for access to a protected RDAP resource.")
    (rdap_dnt_allowed "This claim contains a JSON boolean literal that describes a \"do not track\" request for server-side tracking, logging, or recording of an identity that is presented for access to a protected RDAP resource.")
    ;; W3C VC
    (vc "Verifiable Credential" "As specified in the W3C Recommendation")
    (vp "Verifiable Presentation" "As specified in the W3C Recommendation")
    ;; ETSI NFV-SEC 022
    (at_use_nbr "Number of API requests for which the access token can be used")
    ;; CTA-5009
    (geohash "Geohash String or Array"))
  "Documentation strings for ElDoc.
Each alist member should be a list in any of these formats:
  LIST                     DOCUMENTATION OUTPUT
  (foo \"document\")         \"foo: document\"
  (foo \"name\" \"document\")  \"name: document\"")

(defun jwt--hex-string-to-bytes (hex &optional left-align)
  "Convert a hex string HEX to a byte string.

When LEFT-ALIGN is true, interpret odd length strings greedily
E.g. CCC becomes [204, 12] not [12 204]."
  ;; ambiguous when odd length string
  ;; e.g. CCC is either [12 204], or [204, 12]
  ;; but CCCC is always [204, 204]
  (unless (cl-evenp (length hex))
    (warn "Possibly ambiguous hex string")
    (unless left-align
      (setq hex (concat "0" hex))))
  (let ((res (mapcar (lambda (x)
                       (string-to-number x 16))
                     (seq-partition hex 2))))
    (apply #'vector res)))

(defun jwt--byte-string-to-hex (bytes)
  "Convert a byte string BYTES to a hex string."
  (let (res)
    (dolist (x (seq--into-list bytes))
      ;; should always produce a len 2 string
      (push (format "%02x" x) res))
    (apply #'concat (reverse res))))

(defun jwt--i2osp (x x-len)
  "Encode number X as an X-LEN long list of bytes.

I2OSP = Int to Octal String Primitive.
See: https://datatracker.ietf.org/doc/html/rfc3447#section-4.1"
  (when (> x (expt 256 x-len))
    (error "Integer too large"))
  (let (res
        (rem 0)
        (idx (1- x-len)))
    (while (and (> x 0) (>= idx 0))
      (setq rem (% x (expt 256 idx)))
      (push (/ (- x rem) (expt 256 idx)) res)
      (setq x rem)
      (setq idx (1- idx)))
    (reverse res)))

(defun jwt-sha256 (str)
  "Apply SHA256 interpreting STR as a binary string and returning a binary string."
  (secure-hash 'sha256 (apply #'unibyte-string (string-to-list str)) nil nil 't))

(defun jwt-sha384 (str)
  "Apply SHA384 interpreting STR as a binary string and returning a binary string."
  (secure-hash 'sha384 (apply #'unibyte-string (string-to-list str)) nil nil 't))

(defun jwt-sha512 (str)
  "Apply SHA512 interpreting STR as a binary string and returning a binary string."
  (secure-hash 'sha512 (apply #'unibyte-string (string-to-list str)) nil nil 't))

(define-hmac-function jwt-hs256 jwt-sha256 64 32)

(define-hmac-function jwt-hs384 jwt-sha384 128 48)

(define-hmac-function jwt-hs512 jwt-sha512 128 64)

(defun jwt--os2ip (x)
  "Concat a list of bytes X and convert to number.

OS2IP = Octal String to Int Primitive.
See: https://datatracker.ietf.org/doc/html/rfc3447#section-4.1"
  (string-to-number
   (seq-mapcat (apply-partially #'format "%02x") x 'string)
   16))

(defun jwt--asn-read-ignore (n str)
  "Helper for processing ASN byte string STR.

Skip the first byte of STR which should be N."
  (let ((x (pop str)))
    (unless (= x n)
      (error "Expected %s got %s in %s" n x str)))
  str)

(defun jwt--asn-split-using-len (str)
  "Helper for processing ASN byte string STR.

Assuming first byte of STR is a DER LEN byte, return a cons cell like
`(x . y)' where x is a string with length given by that byte or sequence
and y is the remainder.

See https://en.wikipedia.org/wiki/X.690#DER_encoding"
(let* ((der-byte (pop str))
       len)
  (if (> ?\x80 der-byte)
      (setq len der-byte)
    ;; TODO if exactly 80, then read until 00 00
    (let ((fwd (- der-byte ?\x80)))
      (setq len (jwt--os2ip (take fwd str)))
      (setq str (nthcdr fwd str))))
  ;; next len bytes are the actual number
  (cons (take len str)
        (nthcdr len str))))

(defun jwt-parse-rsa-key (rsa-key-string)
  "Extract RSA modulus and exponent from RSA-KEY-STRING.

This may be either SPKI formatted with prefix BEGIN PUBLIC KEY,
or RSA formatted with prefix BEGIN RSA PUBLIC KEY.

Result is a plist (:n modulus :e exponent)."
  (setq rsa-key-string (string-remove-prefix "-----BEGIN RSA PUBLIC KEY-----"
                                             (string-remove-suffix "-----END RSA PUBLIC KEY-----"
                                                                   (string-trim rsa-key-string))))
  (let* ((is-spki (string-prefix-p "-----BEGIN PUBLIC KEY-----" rsa-key-string))
         (rsa-key-string (string-trim rsa-key-string "-----BEGIN \\(RSA \\)?PUBLIC KEY-----" "-----END \\(RSA \\)?PUBLIC KEY-----"))
         (rsa-key-string (string-trim rsa-key-string))
         (bin-string (string-to-list (base64-decode-string rsa-key-string)))
         ;; drop 24 byte preamble if SPKI format
         ;; TODO ECC keys have a different OID in this preamble
         (bin-string (if is-spki (seq-drop bin-string 24) bin-string))
         result-n
         result-e)

    ;; SEQ LEN L
    (setq bin-string (jwt--asn-read-ignore ?\x30 bin-string))
    (cl-destructuring-bind (seq-content . bin-string-remainder) (jwt--asn-split-using-len bin-string)
      (when bin-string-remainder
        (warn "Expected entire ASN sequence to be key"))
      (setq bin-string seq-content))

    ;; n
    ;; INT LEN L
    (setq bin-string (jwt--asn-read-ignore ?\x02 bin-string))
    (cl-destructuring-bind (int-content . bin-string-remainder) (jwt--asn-split-using-len bin-string)
      (setq result-n (seq-drop-while #'zerop int-content))
      (setq bin-string bin-string-remainder))

    ;; e
    ;; INT LEN L
    (setq bin-string (jwt--asn-read-ignore ?\x02 bin-string))
    (cl-destructuring-bind (int-content . bin-string-remainder) (jwt--asn-split-using-len bin-string)
      (setq result-e (seq-drop-while #'zerop int-content))
      (setq bin-string bin-string-remainder))

    (when bin-string
      (warn "ASN sequence was not empty after processing key parts"))

    `(:n ,(jwt--byte-string-to-hex result-n) :e ,(jwt--byte-string-to-hex result-e))))

(defun jwt--extract-digest-from-pkcs1-hash (input)
  "Return hash digest (as hex) from INPUT (list of bytes)."
  (let* ((input (seq-drop input 2)) ;; always 00 01
         (input (seq-drop-while (apply-partially #'= ?\xFF) input))
         (input (seq-drop-while #'zerop input))
         ;; encoded digest begins
         (input (jwt--asn-read-ignore ?\x30 input))
         (input-and-rest (jwt--asn-split-using-len input))
         (_ (when (cdr input-and-rest) (error "Expected rest to be empty")))
         (input (car input-and-rest))
         ;; identifier
         (input (jwt--asn-read-ignore ?\x30 input))
         (input-and-rest (jwt--asn-split-using-len input))
         (input (cdr input-and-rest))
         ;; ;; null - this is included above
         ;; (input (jwt--asn-read-ignore ?\x05 input))
         ;; ;; 00
         ;; (input (cdr input))
         (input (jwt--asn-read-ignore ?\x04 input))
         (input-and-rest (jwt--asn-split-using-len input)))
    (jwt--byte-string-to-hex (car input-and-rest))))

;; see https://datatracker.ietf.org/doc/html/rfc3447#section-8.2.2
(defun jwt-rsa-verify (public-key hash-algorithm object sig)
  "Check SIG of OBJECT using RSA PUBLIC-KEY and HASH-ALGORITHM.

PUBLIC-KEY must be a plist (:n modulus :e exponent).
HASH-ALGORITHM must be one of `sha256, `sha384, or `sha512.
OBJECT is a string, assumed to be encoded.
SIG is a base64url encoded string."
  (unless (seq-contains-p '(sha256 sha384 sha512)
                          hash-algorithm)
    (error "Unsupported hash algorithm %s" hash-algorithm))
  (let* ((sig-bytes (base64-decode-string sig 't))
         (sig (string-to-number (jwt--byte-string-to-hex sig-bytes) 16))
         (_ (unless (= (string-bytes sig-bytes) (/ (length (plist-get public-key :n)) 2))
              (error "Signature length does not match key length")))
         (n (string-to-number (plist-get public-key :n) 16))
         (e (string-to-number (plist-get public-key :e) 16))
         (hash (secure-hash hash-algorithm object)))

    (let* ((calc-display-working-message nil)
           ;; this is EMSA-PKCS1, so it has extra metadata wrapping the hash
           (message-representative (math-pow-mod sig e n))
           (encoded-message (jwt--i2osp message-representative 256))
           (digest (jwt--extract-digest-from-pkcs1-hash encoded-message)))
      ;; see https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
      (equal digest hash))))

(cl-defstruct jwt-token-json
  "A JWT decoded into JSON strings."
  header
  payload
  signature)

(defun jwt-token-json-header-parsed (token)
  "Get the header slot of TOKEN as a Lisp object."
  (json-parse-string (jwt-token-json-header token)))

(defun jwt-token-json-payload-parsed (token)
  "Get the payload slot of TOKEN as a Lisp object."
  (json-parse-string (jwt-token-json-payload token)))

(defun jwt-to-token-json (token)
  "Decode TOKEN as a `jwt-token-json' struct."
  (condition-case err
   (cl-destructuring-bind (jwt-header jwt-payload jwt-signature) (string-split token "\\.")
     (make-jwt-token-json
      :header (decode-coding-string (base64-decode-string jwt-header 't) 'utf-8)
      :payload (decode-coding-string (base64-decode-string jwt-payload 't) 'utf-8)
      :signature jwt-signature))
   (wrong-number-of-arguments
    (error "Invalid JWT: %s\nexpected 3 parts" token))
   (error
    (error "Invalid JWT: %s\nreason: %s" token (cdr err)))))

(defun jwt--random-bytes (n)
  "Generate random byte string of N chars.

The result is a plain unibyte string, it is not base64 encoded."
  (let (chars)
    (dotimes (_ n)
      (push (cl-random 256) chars))
    (apply #'unibyte-string chars)))

(defun jwt--normalize-string-or-token (string-or-token)
  "Given STRING-OR-TOKEN return as a `jwt-token-json struct."
  (if (jwt-token-json-p string-or-token)
      string-or-token
    (jwt-to-token-json string-or-token)))

(defun jwt-token-time-until-expiry (token &optional lifetime-seconds)
  "Seconds remaining before TOKEN expires.

Result is negative if TOKEN is already expired, positive if still valid,
and nil if expiry time could not be determined.

LIFETIME-SECONDS can be used if token lifetime is specified elsewhere."
  (let* ((token (jwt--normalize-string-or-token token))
         (jwt-payload (jwt-token-json-payload-parsed token))
         (jwt-iat (map-elt jwt-payload "iat"))
         (jwt-exp (map-elt jwt-payload "exp"))
         (time-seconds (time-convert (current-time) 'integer)))
    (cond
     (jwt-exp
      (- jwt-exp time-seconds))
     ((and jwt-iat lifetime-seconds)
      (- (+ jwt-iat lifetime-seconds) time-seconds)))))

(defun jwt-create (payload alg key &optional extra-headers set-iat)
  "Create a JWT with the given PAYLOAD.

Currently only supports signing with HMAC.

ALG must be a string, one of HS256, HS384, HS512.
KEY byte string for HMAC.
EXTRA-HEADERS optional alist of headers to append to the JOSE header.
SET-IAT if non-nil add an iat claim to the payload with current time."
  (let* ((jose-header `((alg . ,alg)
                        (typ . "JWT")
                        ,@extra-headers))
         (jose-header (encode-coding-string (json-serialize jose-header) 'utf-8))
         (payload (if set-iat
                      (cons `(iat . ,(time-convert (current-time) 'integer)) payload)
                    payload))
         (jwt-payload (encode-coding-string (json-serialize payload) 'utf-8))
         (content (concat (base64url-encode-string jose-header 't) "." (base64url-encode-string jwt-payload 't)))
         (signing-fn (pcase (upcase alg)
                       ("HS256" #'jwt-hs256)
                       ("HS384" #'jwt-hs384)
                       ("HS512" #'jwt-hs512)
                       (_ (error "JWT signing with %s is not supported" alg))))
         (signature (funcall signing-fn content key))
         (signature (base64url-encode-string signature 't)))
    (concat content "." signature)))

(defun jwt-verify-signature (token key)
  "Check the signature in TOKEN using KEY."
  (let* ((token-json (jwt--normalize-string-or-token token))
         (parsed-header (jwt-token-json-header-parsed token-json))
         (alg (upcase (map-elt parsed-header "alg")))
         (token-parts (string-split token "\\."))
         (encoded-content (string-join (seq-take token-parts 2) "."))
         (sig (seq-elt token-parts 2)))
    (pcase alg
     ;; HMAC
     ("HS256"
      (equal
       sig
       (base64url-encode-string (jwt-hs256 encoded-content key) 't)))
     ("HS384"
      (equal
       sig
       (base64url-encode-string (jwt-hs384 encoded-content key) 't)))
     ("HS512"
      (equal
       sig
       (base64url-encode-string (jwt-hs512 encoded-content key) 't)))
     ;; RSA
     ("RS256"
      (jwt-rsa-verify (jwt-parse-rsa-key key) 'sha256 encoded-content sig))
     ("RS384"
      (jwt-rsa-verify (jwt-parse-rsa-key key) 'sha384 encoded-content sig))
     ("RS512"
      (jwt-rsa-verify (jwt-parse-rsa-key key) 'sha512 encoded-content sig))
     (_ (error "Unkown JWT algorithm %s" alg)))))

(defun jwt-encoded-token-p (test-string)
  "True if TEST-STRING decodes to a JWT-like object.

This does not check every aspect of RFC7519 (JWT) and RFC7515 (JWS)
compliance.

Specifically it checks that TEST-STRING has
- three base64url encoded JSON parts
- a JOSE header with alg claim"
  (ignore-errors
    (let* ((maybe-token (jwt-to-token-json test-string))
           (jose-header (jwt-token-json-header-parsed maybe-token))
           (payload (jwt-token-json-payload-parsed maybe-token))
           (signature (jwt-token-json-signature maybe-token)))
      (and
       ;; Only mandatory JOSE claim
       (map-contains-key jose-header "alg")
       ;; All payload claims are optional, so just check that it parses
       payload
       ;; Signature is allowed to be "" for unsecured tokens
       signature
       't))))

(defvar jwt-local-token nil "Buffer token string when in a JWT buffer.")
(make-variable-buffer-local 'jwt-local-token)

;;;###autoload
(defun jwt-decode (token)
  "Decode TOKEN and display results in a buffer."
  (interactive "MToken: ")
  (cl-assert (stringp token) 't)
  (with-current-buffer (generate-new-buffer "*JWT contents*")
    (let ((token-json (jwt-to-token-json token)))
      (insert (format "{ \"_header\": %s, \"_payload\": %s, \"_signature\": \"%s\" }"
                      (jwt-token-json-header token-json)
                      (jwt-token-json-payload token-json)
                      (jwt-token-json-signature token-json)))
      ;; (jsonc-mode) ;; not included -- is it worth including?
      (js-json-mode)
      (json-pretty-print-buffer)
      (setq jwt-local-token token
            buffer-read-only 't)
      (jwt-minor-mode)
      (pop-to-buffer (current-buffer)))))

;;;###autoload
(defun jwt-decode-at-point ()
  "Decode token at point and display results in a buffer."
  (interactive)
  ;; FIXME: depending on the mode sexp-at-point may miss parts of the token
  (let* ((maybe-token (sexp-at-point))
         (maybe-token (if (symbolp maybe-token)
                          (symbol-name maybe-token)
                        (if (stringp maybe-token)
                            maybe-token
                          (error "Token must be a string"))))
         (maybe-token (string-trim maybe-token "\"" "\""))
         (maybe-token (string-trim maybe-token "'" "'")))
    (unless maybe-token
      (message "No token selected"))
    (jwt-decode maybe-token)))

;;;###autoload
(defun jwt-decode-region (start end)
  "Decode token in region START to END and display results in a buffer."
  (interactive "r")
  (when (and (called-interactively-p 'interactive) (not (region-active-p)))
             (user-error "No active region"))
  (jwt-decode
   (string-trim (buffer-substring-no-properties start end) "[\"'`]+" "[\"'`]+")))

(defun jwt-verify-current-token (key)
  "Verfiy the currently displayed token using KEY."
  (interactive "Mkey: ")
  (unless jwt-local-token
    (error "No token found to verify"))
  (unless (string-prefix-p "-----" key)
    (message "Assuming base64 encoded HMAC key")
    (setq key (base64-decode-string key)))
  (if (jwt-verify-signature jwt-local-token key)
      (message "Token signature OK")
    (message "Token signature INVALID")))

(defun jwt--eldoc (callback &rest _ignored)
  "Document defined claims with ElDoc CALLBACK."
  (when-let* ((maybe-claim (sexp-at-point))
              (maybe-doc (cdr (assoc maybe-claim jwt--defined-claims-alist))))
    (let* ((full-name (when (eq 2 (length maybe-doc))
                        (pop maybe-doc)))
           (full-name (or full-name maybe-claim))
           (doco (car maybe-doc)))
      (funcall callback doco :thing full-name))))

(defcustom jwt-enable-overlays t
  "If non-nil, display overlays."
  :type 'boolean
  :group 'jwt-el)

(defun jwt--format-time (time)
  "Make numeric TIME human readable."
  (when (stringp time)
    (setq time (string-to-number time)))
  (format-time-string "%Y-%m-%d %a %H:%M:%S %Z" time))

(defun jwt--make-claim-regexp (claim)
  "Return a regexp matching a line with JSON property CLAIM.
The value of the property is in the first capture group.
Assumes JSON is formatted so that there is a single property per line."
  (rx "\"" (literal claim) "\"" (* space) ":"
      (* space) (? "\"") (group (+ word)) (? "\"") (? ",")))

(defface jwt-annotation
  '((default :box
             (:line-width (1 . 1)
                          :color nil
                          :style nil))
    (((class color) (background light)) :foreground "SkyBlue4")
    (((class color) (background  dark)) :foreground "LightSkyBlue1"))
  "Face for JWT claim annotation overlays."
  :group 'jwt-el)

(defface jwt-annotation-expired
  '((t :inherit jwt-annotation :foreground "red" ))
  "Face for expired overlay."
  :group 'jwt-el)

(defface jwt-annotation-not-valid
  '((t :inherit jwt-annotation :foreground "orange" ))
  "Face for overlay for when nbf time has not been reached."
  :group 'jwt-el)

(defvar jwt--annotation-claim-functions
  (list
   (list :regexp (jwt--make-claim-regexp "nbf")
         :function (lambda ()
                     (let* ((time (string-to-number (match-string-no-properties 1)))
                            (formatted-time (jwt--format-time time)))
                       (if (> time (float-time))
                           (propertize (format "Not valid until %s" formatted-time) 'face 'jwt-annotation-not-valid)
                         (propertize (format "Not before %s" formatted-time) 'face 'jwt-annotation)))))
   (list :regexp (jwt--make-claim-regexp "iat")
         :function (lambda ()
                     (let* ((time (match-string-no-properties 1))
                            (formatted-time (jwt--format-time time)))
                       (propertize (format "Issued at %s" formatted-time) 'face 'jwt-annotation))))
   (list :regexp (jwt--make-claim-regexp "exp")
         :function (lambda ()
                     (let* ((time (string-to-number (match-string-no-properties 1)))
                            (formatted-time (jwt--format-time time)))
                       (if (< time (float-time))
                           (propertize (format "Expired %s" formatted-time) 'face 'jwt-annotation-expired)
                         (propertize (format "Expires at %s" formatted-time) 'face 'jwt-annotation))))))
  "List of forms like (:regexp R :function F).
Function forms F should take no arguments and return a propertized string.
Match data will be set with the result of matching R.")

(defun jwt--annotation-add-overlays (beg end)
  "Add JWT related overlays between BEG and END."
  (save-excursion
    (goto-char beg)
    (dolist (claim-fn jwt--annotation-claim-functions)
      (let ((claim-rx (plist-get claim-fn :regexp))
            (claim-fn (plist-get claim-fn :function)))
        (save-match-data
          (while (re-search-forward claim-rx end t)
            (let ((ov (make-overlay (match-beginning 0) (match-end 0))))
              (overlay-put ov 'category 'jwt)
              (overlay-put ov 'after-string (concat " " (funcall claim-fn))))))))))

(defun jwt--annotation-remove-overlays (beg end)
  "Cleanup all JWT related overlays between BEG and END."
  (remove-overlays beg end 'category 'jwt))

(defun jwt--update-overlays (beg end)
  "Update JWT related overlays between BEG and END."
  (jwt--annotation-remove-overlays beg end)
  (when jwt-enable-overlays
    (jwt--annotation-add-overlays beg end)))

(define-minor-mode jwt-minor-mode
  "Display decoded contents of JWTs."
  :interactive nil
  :keymap (define-keymap
            "C-c C-c" #'jwt-verify-current-token)
  :lighter " JWT-decoded"
  (add-hook 'eldoc-documentation-functions #'jwt--eldoc nil t)
  (jit-lock-register 'jwt--update-overlays)
  (eldoc-mode))

(provide 'jwt)

;;; jwt.el ends here
