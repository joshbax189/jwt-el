(require 'ert)
(require 'jwt)

(ert-deftest jwt-create/test-1 ()
  "Matches output hs256"
  (let* ((key (jwt-random-key 64))
         (payload '((sub . "1234567890") (name . "John Doe") (iat . 1516239022)))
         (token (jwt-create payload "hs256" key))
         (token-json (jwt-to-token-json token)))
    (message "key %s" (base64-encode-string key 't))
    (message "token is %s" token)
    (should (equal
             (jwt-token-json-header token-json)
             "{\"alg\":\"hs256\",\"typ\":\"JWT\"}"))
    (should (equal
             (jwt-token-json-payload token-json)
             (json-encode payload)))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-hs256/test ()
  "correctness"
  (should (equal
           "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
           (jwt--byte-string-to-hex (jwt-hs256 (encode-coding-string "The quick brown fox jumps over the lazy dog" 'ascii) (encode-coding-string "key" 'ascii))))))

(ert-deftest jwt-hs256/test-utf-8 ()
  "correctness"
  (should (equal
           "a816481d563291d584bf019c50e4143def701d72952dc3bbab32e2c5178c1651"
           (jwt--byte-string-to-hex (jwt-hs256 (encode-coding-string "家" 'utf-8) (encode-coding-string "key" 'ascii)))))
  (should (equal
           "c280cd885e9434858bdd8513cea6a99c90925b3f67b16896cb6bc25f50abe15d"
           (jwt--byte-string-to-hex (jwt-hs256 (encode-coding-string "foobar123" 'ascii) (encode-coding-string "家" 'utf-8))))))

(ert-deftest jwt-hs512/test ()
  "correctness"
  (should (equal
           "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"
           (jwt--byte-string-to-hex (jwt-hs512 (encode-coding-string "The quick brown fox jumps over the lazy dog" 'ascii) (encode-coding-string "key" 'ascii))))))

(ert-deftest jwt-hs512/test-utf-8 ()
  "correctness"
  (should (equal
           "7d0dfb8c4a6e53351c14e16889628d30289e2d1b5fe633de02ac8edf7cdbd6ffb6838e7aa6d205d017a74fe081a37c08f39bdc2c79857c77a59bc493d84eeab5"
           (jwt--byte-string-to-hex (jwt-hs512 (encode-coding-string "家" 'utf-8) (encode-coding-string "key" 'ascii)))))
  (should (equal
           "ff6162f2b751750c6766512f359de888ce433f3e7cb590f627ac3d74cdea4a4deeaf072f69de6ef5c7ae1aebdbec0b1a934feeb448abdb19f765ef1374ebe2f3"
           (jwt--byte-string-to-hex (jwt-hs512 (encode-coding-string "foobar123" 'ascii) (encode-coding-string "家" 'utf-8))))))

(ert-deftest jwt--byte-string-to-hex/test ()
  "Check, as this is used in tests."
  (should (equal "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
                 (jwt--byte-string-to-hex (jwt--hex-string-to-bytes "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"))))
  (should (equal "08"
                 (jwt--byte-string-to-hex (string 8)))))
