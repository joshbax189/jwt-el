(require 'ert)
(require 'jwt)

(ert-deftest jwt-create/test-1 ()
  "Matches output hs256"
  (let* ((key (jwt--random-bytes 64))
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

(ert-deftest jwt-parse-spki-rsa/test ()
  "Check against example"
  (let* ((test-key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61BjmfXGEvWmegnBGSuS
+rU9soUg2FnODva32D1AqhwdziwHINFaD1MVlcrYG6XRKfkcxnaXGfFDWHLEvNBS
EVCgJjtHAGZIm5GL/KA86KDp/CwDFMSwluowcXwDwoyinmeOY9eKyh6aY72xJh7n
oLBBq1N0bWi1e2i+83txOCg4yV2oVXhBo8pYEJ8LT3el6Smxol3C1oFMVdwPgc0v
Tl25XucMcG/ALE/KNY6pqC2AQ6R2ERlVgPiUWOPatVkt7+Bs3h5Ramxh7XjBOXeu
lmCpGSynXNcpZ/06+vofGi/2MlpQZNhHAo8eayMp6FcvNucIpUndo1X8dKMv3Y26
ZQIDAQAB
-----END PUBLIC KEY-----")
        (result (jwt-parse-spki-rsa test-key)))
    (print result)
    (should (equal (jwt--hex-string-to-bytes (plist-get result :n))
                   (jwt--hex-string-to-bytes "EB506399F5C612F5A67A09C1192B92FAB53DB28520D859CE0EF6B7D83D40AA1C1DCE2C0720D15A0F531595CAD81BA5D129F91CC6769719F1435872C4BCD0521150A0263B470066489B918BFCA03CE8A0E9FC2C0314C4B096EA30717C03C28CA29E678E63D78ACA1E9A63BDB1261EE7A0B041AB53746D68B57B68BEF37B71382838C95DA8557841A3CA58109F0B4F77A5E929B1A25DC2D6814C55DC0F81CD2F4E5DB95EE70C706FC02C4FCA358EA9A82D8043A47611195580F89458E3DAB5592DEFE06CDE1E516A6C61ED78C13977AE9660A9192CA75CD72967FD3AFAFA1F1A2FF6325A5064D847028F1E6B2329E8572F36E708A549DDA355FC74A32FDD8DBA65")))
    (should (equal (plist-get result :e)
                   "010001"))))

(ert-deftest jwt-rsa-verify/test ()
  "Check against example"
  (let* ((test-key "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----"))
    (should (jwt-rsa-verify
             (jwt-parse-spki-rsa test-key)
             ;; encoded jwt
             "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
             ;; signature
             "NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"))))

;; TODO
(ert-deftest jwt-verify-signature/test-hmac-256 ()
  "Verify an HS256 signed JWT"
  (let ((token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        (key "your-256-bit-secret"))
    (should (jwt-verify-signature token key))))

(ert-deftest jwt-verify-signature/test-rsa-256 ()
  "Verify an RS256 signed JWT"
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
  "Verify an RS384 signed JWT"
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
  "Verify an RS512 signed JWT"
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

(ert-deftest jwt-test-mod ()
  ""
  (let ((a 6622260807334685525462658416881755917064989675168862694367684881905120344278656217053427246303503958308453943477128116659043419198582105147016038754813699894022702949771355720642601696828155086162526892170185968328740649994212164209155891050607969295892537221458154141762992538400808669702249802215397341390193451594023143049622811927543830642188129384952776294943747339082861101349805970986437816528116678035980535520589894009375651613472092219145400626520800252613002938040236543084381796898249609621643088834244614988874362749203676482301576477089003569320756953006800272822214600319537925561496217487516386918801)
        (b 65537)
        (m 297056429939040947991047334197581225628107021573849359042679698093131908015712695688944173317630555849768647118986535684992447654339728777985990170679511111819558063246667855023730127805401069042322764200545883378826983730553730138478384327116513143842816383440639376515039682874046227217032079079790098143158087443017552531393264852461292775129262080851633535934010704122673027067442627059982393297716922243940155855127430302323883824137412883916794359982603439112095116831297809626059569444750808699678211904501083183234323797142810155862553705570600021649944369726123996534870137000784980673984909570977377882585701))
    (should (equal (math-pow-mod a b m)
                   126810842194940389644913010899340971119608450659708763694806648763560074505340734161566843447053045334678159241427840788715427873134181840750555918034315576316381774978769552950167693019128039628160861024658441403614760339186415161533311605099158849253197257366494363741673283759583077306653978425416256370652173638161222149719376410568257431374756750641057755223775758272402959954262042333379168469326695771964026139712872160575092289879885560042408851593192099871877091291605100261799462150215961029711949915827959807788673603267246042504428786120368772915494984776027687528854058419273195857785955019847065731985323
                   ))))
