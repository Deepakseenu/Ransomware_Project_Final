/*
=============================================
YARA Rules for Ransomware & Webshell Detection
Optimized & Cleaned – Honeypot Project
=============================================
*/

rule ransom_note_file_name
{
    meta:
        author = "student"
        category = "ransomware"
        description = "Detect common ransom note filename patterns"

    strings:
        $r1 = /README.*DECRYPT/i
        $r2 = /HOW_TO_DECRYPT/i
        $r3 = /README-FOR-DECRYPT/i
        $r4 = /_HOW_TO_RESTORE_/i

    condition:
        any of ($r*) and filesize < 20000
}

rule ransom_note_content
{
    meta:
        author = "student"
        category = "ransomware"
        description = "Detect ransom note contents and crypto references"

    strings:
        $s1 = "your files have been encrypted" wide ascii
        $s2 = "decrypt" wide ascii
        $s3 = "contact" wide ascii
        $s4 = "bitcoin" wide ascii
        $s5 = /[A-Za-z0-9]{26,35}/ ascii   // crypto wallet
        $s6 = "send BTC" wide ascii
        $s7 = /how to (pay|contact)/i

    condition:
        any of ($s*) and filesize < 60000
}

rule encrypted_extension_marker
{
    meta:
        author = "student"
        category = "ransomware"

    strings:
        $e1 = ".enc"
        $e2 = ".locked"
        $e3 = ".crypt"
        $e4 = ".crypted"

    condition:
        any of ($e*) and filesize < 300000
}

rule long_base64_blob
{
    meta:
        author = "student"
        category = "payload"
        description = "Long base64 blobs"

    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/

    condition:
        $b64 and filesize > 1024
}

rule embedded_rsa_pubkey
{
    meta:
        category = "crypto"
        author = "student"

    strings:
        $pem_pub = "-----BEGIN PUBLIC KEY-----"
        $pem_rsa = "-----BEGIN RSA PUBLIC KEY-----"
        $pem_any = "-----BEGIN CERTIFICATE-----"

    condition:
        any of ($pem_pub, $pem_rsa, $pem_any)
}

rule php_webshell_pattern
{
    meta:
        category = "webshell"
        author = "student"

    strings:
        $s1 = "eval("
        $s2 = "base64_decode("
        $s3 = "shell_exec("
        $s4 = "passthru("
        $s5 = "exec("
        $s6 = "preg_replace("
        $s7 = "assert("
        $s8 = "system("

    condition:
        any of ($s*) and filesize < 300000
}

rule php_webshell_obfuscation
{
    meta:
        category = "webshell"
        author = "student"

    strings:
        $hex_seq = /\\x[0-9A-Fa-f]{50,}/
        $chr_calls = /(chr\(|chr\s*\()/i
        $rot13 = /str_rot13\(/i
        $many_chr = /(chr\(\d+\)\s*\.\s*){10,}/

    condition:
        any of ($hex_seq, $chr_calls, $rot13, $many_chr)
}

rule ransomware_key_artifact
{
    meta:
        category = "ransomware"
        author = "student"

    strings:
        $k1 = "ENCRYPTION_KEY"
        $k2 = "PRIVATE_KEY"
        $k3 = "PUBLIC_KEY"
        $k4 = "KEY:"
        $k5 = /AES-256/i
        $k6 = /ChaCha20/i

    condition:
        any of ($k*)
}

rule common_webshell_names_in_content
{
    meta:
        category = "webshell"
        author = "student"

    strings:
        $u1 = "uploaded_shell"
        $u2 = "webshell"
        $u3 = "cmd="
        $u4 = "phpinfo("

    condition:
        any of ($u1, $u2, $u3, $u4)
}

rule repeated_binary_marker
{
    meta:
        category = "payload"
        author = "student"

    strings:
        $pk = "PK\x03\x04"

    condition:
        #pk > 10
}
