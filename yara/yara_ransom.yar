/*
Improved YARA rules for Ransomware & Webshell Detection
- Conservative defaults to reduce false positives
- Combined high-confidence rule
- File size limits where appropriate
Author: Assistant (reviewed & improved from original)
*/

rule ransom_note_file_name
{
    meta:
        author = "assistant"
        category = "ransomware"
        description = "Detect common ransom note filename patterns (conservative)"
        score = 10

    strings:
        $r1 = /README([_\s-])?DECRYPT/i
        $r2 = /HOW[_\s]?TO[_\s]?DECRYPT/i
        $r3 = /README[-_]FOR[-_]DECRYPT/i
        $r4 = /HOW[_\s]?TO[_\s]?RESTORE/i

    condition:
        any of ($r*) and filesize < 200KB
}

rule ransom_note_content
{
    meta:
        author = "assistant"
        category = "ransomware"
        description = "Ransom note phrases and crypto/payment markers (requires 2 phrase matches)"
        score = 20

    strings:
        $s1 = "your files have been encrypted" wide ascii nocase
        $s2 = "we have encrypted" wide ascii nocase
        $s3 = "private key" wide ascii nocase
        $s4 = "bitcoin" wide ascii nocase
        $s5 = /[13][A-HJ-NP-Za-km-z1-9]{25,34}/ ascii   /* common BTC address approx. */
        $s6 = "how to restore" wide ascii nocase
        $s7 = /readme[_\s-]?decrypt/i

    condition:
        #s* >= 2 and filesize < 400KB
}

rule encrypted_extension_marker
{
    meta:
        author = "assistant"
        category = "ransomware"
        description = "Suspicious file extensions appended by ransomware (conservative list)"
        score = 8

    strings:
        $e1 = /\.enc$/i
        $e2 = /\.locked$/i
        $e3 = /\.crypt(ed)?$/i
        $e4 = /\.(lockbit|conti|blackcat|recovery|decryptme)$/i

    condition:
        any of ($e*) and filesize < 1MB
}

rule long_base64_blob
{
    meta:
        author = "assistant"
        category = "payload"
        description = "Long base64-like blob (require long run + nearby suspicious token to reduce FP)"
        score = 6

    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
        $susp = /eval\(|base64_decode|gzinflate|gzuncompress|system\(|exec\(|shell_exec\(/i

    condition:
        $b64 and (1 of ($susp)) and filesize < 5MB
}

rule embedded_rsa_pubkey
{
    meta:
        category = "crypto"
        author = "assistant"
        description = "Embedded PEM/RSA public key markers"
        score = 12

    strings:
        $pem_pub  = "-----BEGIN PUBLIC KEY-----"
        $pem_rsa  = "-----BEGIN RSA PUBLIC KEY-----"
        $pem_cert = "-----BEGIN CERTIFICATE-----"

    condition:
        any of ($pem_pub, $pem_rsa, $pem_cert) and filesize < 2MB
}

rule php_webshell_pattern
{
    meta:
        category = "webshell"
        author = "assistant"
        description = "PHP webshell-like API usage. Require >=2 suspicious functions to reduce FP."
        score = 10

    strings:
        $s1 = /eval\s*\(/i
        $s2 = /base64_decode\s*\(/i
        $s3 = /shell_exec\s*\(/i
        $s4 = /passthru\s*\(/i
        $s5 = /exec\s*\(/i
        $s6 = /preg_replace\s*\(/i
        $s7 = /assert\s*\(/i
        $s8 = /system\s*\(/i

    condition:
        (#s* >= 2) and filesize < 500KB
}

rule php_webshell_obfuscation
{
    meta:
        category = "webshell"
        author = "assistant"
        description = "PHP obfuscation patterns (require either long hex sequences OR repeated chr() calls plus rot13/str_rot13)"
        score = 14

    strings:
        $hex_seq   = /\\x[0-9A-Fa-f]{40,}/
        $chr_calls = /(chr\s*\(\s*\d+\s*\)\s*(?:\.\s*)?){8,}/i
        $rot13     = /str_rot13\s*\(/i
        $many_chr  = /(chr\(\d+\)\s*\.\s*){10,}/i

    condition:
        ( $hex_seq and filesize < 1MB ) or ( ($chr_calls or $many_chr) and $rot13 )
}

rule ransomware_key_artifact
{
    meta:
        category = "ransomware"
        author = "assistant"
        description = "Keyword artifacts indicating crypto key material or constants"
        score = 8

    strings:
        $k1 = "ENCRYPTION_KEY" nocase
        $k2 = "PRIVATE_KEY" nocase
        $k3 = "PUBLIC_KEY" nocase
        $k4 = /KEY[:=]\s*[A-Za-z0-9\-\_]{8,}/
        $k5 = /AES[\-\s]?256/i
        $k6 = /ChaCha20/i

    condition:
        any of ($k*)
}

rule common_webshell_names_in_content
{
    meta:
        category = "webshell"
        author = "assistant"
        description = "Common webshell artifact names or suspicious query patterns (conservative)"
        score = 6

    strings:
        $u1 = /uploaded[_\s-]?shell/i
        $u2 = /webshell/i
        $u3 = /cmd\s*=/i
        $u4 = /phpinfo\s*\(/i

    condition:
        any of ($u*) and filesize < 300KB
}

rule repeated_binary_marker
{
    meta:
        category = "payload"
        author = "assistant"
        description = "Multiple zip local file headers (PK..). Useful to detect many embedded zips/archives."
        score = 4

    strings:
        $pk = "PK\x03\x04"

    condition:
        (#pk > 8) and filesize < 50MB
}

/* High-confidence combined rule: require at least two medium/strong signals */
rule ransomware_high_confidence
{
    meta:
        author = "assistant"
        category = "ransomware"
        description = "Require combination of file name/content/extension/crypto or webshell+obfuscation to flag high confidence"
        score = 50

    condition:
        ( ransom_note_file_name and ransom_note_content ) or
        ( ransom_note_content and encrypted_extension_marker ) or
        ( php_webshell_pattern and php_webshell_obfuscation ) or
        ( embedded_rsa_pubkey and long_base64_blob )
}
