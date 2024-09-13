;;; jwt-test.el --- Unit tests for JWT.el -*- lexical-binding: t -*-

;; Author: Josh Bax

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

;;; Code:
(require 'ert)
(require 'jwt)

(ert-deftest jwt-create/test-hs256 ()
  "Decoded output should match input using hs256."
  (let* ((key (jwt--random-bytes 64))
         (payload '((sub . "1234567890") (name . "John Doe") (iat . 1516239022)))
         (token (jwt-create payload "hs256" key))
         (token-json (jwt-to-token-json token)))
    (should (equal
             (jwt-token-json-header token-json)
             "{\"alg\":\"hs256\",\"typ\":\"JWT\"}"))
    (should (equal
             (jwt-token-json-payload token-json)
             (json-encode payload)))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-create/test-iat ()
  "Should append iat field."
  (let* ((key (jwt--random-bytes 64))
         (payload '((sub . "1234567890") (name . "John Doe") (iat . 1516239022)))
         (token (jwt-create payload "hs256" key nil 't))
         (token-json (jwt-to-token-json token)))
    (should (map-elt (json-parse-string (jwt-token-json-payload token-json)) "iat"))))

(ert-deftest jwt-create/test-hs512 ()
  "Decoded output should match input using hs512."
  (let* ((key (jwt--random-bytes 64))
         (payload '((sub . "1234567890") (name . "John Doe") (iat . 1516239022)))
         (token (jwt-create payload "hs512" key))
         (token-json (jwt-to-token-json token)))
    (should (equal
             (jwt-token-json-header token-json)
             "{\"alg\":\"hs512\",\"typ\":\"JWT\"}"))
    (should (equal
             (jwt-token-json-payload token-json)
             (json-encode payload)))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-hs256/test ()
  "Should match example output."
  (let ((test-input
         (encode-coding-string
          "The quick brown fox jumps over the lazy dog" 'ascii))
        (test-key (encode-coding-string "key" 'ascii))
        (test-output
         "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"))
    (should
     (equal
      test-output
      (jwt--byte-string-to-hex (jwt-hs256 test-input test-key))))))

(ert-deftest jwt-hs256/test-utf-8 ()
  "Should match example UTF-8 output."
  (should (equal
           "a816481d563291d584bf019c50e4143def701d72952dc3bbab32e2c5178c1651"
           (jwt--byte-string-to-hex (jwt-hs256 (encode-coding-string "家" 'utf-8) (encode-coding-string "key" 'ascii)))))
  (should (equal
           "c280cd885e9434858bdd8513cea6a99c90925b3f67b16896cb6bc25f50abe15d"
           (jwt--byte-string-to-hex (jwt-hs256 (encode-coding-string "foobar123" 'ascii) (encode-coding-string "家" 'utf-8))))))

(ert-deftest jwt-hs512/test ()
  "Should match example output."
  (let ((test-input
         (encode-coding-string
          "The quick brown fox jumps over the lazy dog" 'ascii))
        (test-key (encode-coding-string "key" 'ascii))
        (test-output
         "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"))
    (should
     (equal
      test-output
      (jwt--byte-string-to-hex (jwt-hs512 test-input test-key))))))

(ert-deftest jwt-hs512/test-utf-8 ()
  "Should match example UTF-8 output."
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
  ;; test for correct padding too
  (should (equal "08"
                 (jwt--byte-string-to-hex (string 8)))))

(ert-deftest jwt-parse-rsa-key/test-spki-format ()
  "Check against example."
  (let* ((test-key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS
+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS
EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n
oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v
Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu
lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26
ZQIDAQAB
-----END PUBLIC KEY-----")
        (result (jwt-parse-rsa-key test-key)))
    (should (equal (jwt--hex-string-to-bytes (plist-get result :n))
                   (jwt--hex-string-to-bytes "EB506399F5C612F5A67A09C1192B92FAB53DB28520D859CE0EF6B7D83D40AA1C1DCE2C0720D15A0F531595CAD81BA5D129F91CC6769719F1435872C4BCD0521150A0263B470066489B918BFCA03CE8A0E9FC2C0314C4B096EA30717C03C28CA29E678E63D78ACA1E9A63BDB1261EE7A0B041AB53746D68B57B68BEF37B71382838C95DA8557841A3CA58109F0B4F77A5E929B1A25DC2D6814C55DC0F81CD2F4E5DB95EE70C706FC02C4FCA358EA9A82D8043A47611195580F89458E3DAB5592DEFE06CDE1E516A6C61ED78C13977AE9660A9192CA75CD72967FD3AFAFA1F1A2FF6325A5064D847028F1E6B2329E8572F36E708A549DDA355FC74A32FDD8DBA65")))
    (should (equal (plist-get result :e)
                   "010001"))))

(ert-deftest jwt-parse-rsa-key/test-rsa-format ()
  "Check against example."
  (let* ((test-key "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA61BjmfXGEvWmegnBGSuS+rU9soUg2FnODva32D1AqhwdziwHINFa
D1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBSEVCgJjtHAGZIm5GL/KA86KDp/CwDFMSw
luowcXwDwoyinmeOY9eKyh6aY72xJh7noLBBq1N0bWi1e2i+83txOCg4yV2oVXhB
o8pYEJ8LT3el6Smxol3C1oFMVdwPgc0vTl25XucMcG/ALE/KNY6pqC2AQ6R2ERlV
gPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeulmCpGSynXNcpZ/06+vofGi/2MlpQZNhH
Ao8eayMp6FcvNucIpUndo1X8dKMv3Y26ZQIDAQAB
-----END RSA PUBLIC KEY-----")
        (result (jwt-parse-rsa-key test-key)))
    (should (equal (jwt--hex-string-to-bytes (plist-get result :n))
                   (jwt--hex-string-to-bytes "EB506399F5C612F5A67A09C1192B92FAB53DB28520D859CE0EF6B7D83D40AA1C1DCE2C0720D15A0F531595CAD81BA5D129F91CC6769719F1435872C4BCD0521150A0263B470066489B918BFCA03CE8A0E9FC2C0314C4B096EA30717C03C28CA29E678E63D78ACA1E9A63BDB1261EE7A0B041AB53746D68B57B68BEF37B71382838C95DA8557841A3CA58109F0B4F77A5E929B1A25DC2D6814C55DC0F81CD2F4E5DB95EE70C706FC02C4FCA358EA9A82D8043A47611195580F89458E3DAB5592DEFE06CDE1E516A6C61ED78C13977AE9660A9192CA75CD72967FD3AFAFA1F1A2FF6325A5064D847028F1E6B2329E8572F36E708A549DDA355FC74A32FDD8DBA65")))
    (should (equal (plist-get result :e)
                   "010001"))))

(ert-deftest jwt-rsa-verify/test ()
  "Check against example."
  (let ((test-key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----")
        (encoded-jwt "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0")
        (signature "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"))
    (should (jwt-rsa-verify
             (jwt-parse-rsa-key test-key)
             'sha256
             encoded-jwt
             signature))))

(ert-deftest jwt-verify-signature/test-hmac-256 ()
  "Verify an HS256 signed JWT."
  (let ((token     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        (key "your-256-bit-secret"))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-verify-signature/test-hmac-384 ()
  "Verify an HS384 signed JWT."
  (let ((token "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh")
        (key "your-384-bit-secret"))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-verify-signature/test-hmac-512 ()
  "Verify an HS512 signed JWT."
  (let ((token "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg")
        (key "your-512-bit-secret"))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-verify-signature/test-rsa-256 ()
  "Verify an RS256 signed JWT."
  (let ((token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ")
        (key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----"))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-verify-signature/test-rsa-384 ()
  "Verify an RS384 signed JWT."
  (let ((token "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJhh994RAPzCG0hmQ")
        (key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----"))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-verify-signature/test-rsa-512 ()
  "Verify an RS512 signed JWT."
  (let ((token "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ")
        (key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----"))
    (should (jwt-verify-signature token key))))

(provide 'jwt-test)

;;; jwt-test.el ends here
