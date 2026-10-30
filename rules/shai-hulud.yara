rule ShaiHulud_Source_Or_Plain
{
  meta:
    description = "Source atau build tanpa scramble"
  strings:
    $a = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" ascii wide
    $b = "git-tanstack.com" ascii wide
    $c = "thebeautifulmarchoftime" ascii wide
    $c2 = "thebeautifulsnadsoftime" ascii wide
    $d = "opensearch_init.js" ascii wide
    $e = "__DAEMONIZED" ascii wide
    $f = "gh-token-monitor" ascii wide
    $g2 = "Runner.Worker" ascii wide
    $s1 = "AmazonSSM.GetParameters" ascii wide
    $s2 = "secretsmanager.GetSecretValue" ascii wide
    $s3 = "fulcio.sigstore.dev" ascii wide
    $s4 = "rekor.sigstore.dev" ascii wide
  condition:
    2 of them
}

rule ShaiHulud_C2_RSA_PublicKeys
{
  meta:
    description = "Kunci publik RSA-4096 milik C2 Shai-Hulud (enc_key dan verify_key)"
  strings:
    // Header base64 SPKI enc_key.pub
    $k1 = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlBPLx4Cz7" ascii
    // Header base64 SPKI verify_key.pub
    $k2 = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAm1ThuFsx" ascii
  condition:
    any of them
}

rule ShaiHulud_Scramble_PRNG_Pipeline
{
  meta:
    description = "Pipeline dan artefak decoder/scrambler polialfabetik Shai-Hulud"
  strings:
    $salt = "svksjrhjkcejg" ascii
    $ph = "__SCRAMBLE_BUILD_PASSPHRASE__" ascii
    $pae = "DSSEv1 28 application/vnd.in-toto+json" ascii
    $bundle = "application/vnd.dev.sigstore.bundle.v0.3+json" ascii
  condition:
    any of them
}

rule ShaiHulud_Dropped_Artifacts
{
  meta:
    description = "File aset worm di disk (loader/hook/workflow/monitor)"
  strings:
    $w1 = "toJSON(secrets)" ascii
    $w2 = "format-results" ascii
    $h1 = "node .vscode/setup.mjs" ascii
    $h2 = "node .claude/setup.mjs" ascii
    $m1 = "gh-token-monitor" ascii
    $m2 = "eval \"$HANDLER\"" ascii
    $l1 = "bun-v1.3.13" ascii
    $l2 = "ai_init.js" ascii
    $p1 = "Runner.Worker" ascii
    $p2 = "/proc/{pid}/mem" ascii
  condition:
    ($w1 and $w2) or $h1 or $h2 or ($m1 and $m2) or ($l1 and $l2) or ($p1 and $p2)
}

rule ShaiHulud_Behavioural_Crypto_Envelope
{
  meta:
    description = "Eksfil gzip + AES-256-GCM + RSA-OAEP-SHA256 plus regex token CI"
  strings:
    $g = "aes-256-gcm" ascii
    $r = "RSA_PKCS1_OAEP_PADDING" ascii
    $o = "oaepHash" ascii
    $t1 = "gh[op]_" ascii
    $t2 = "npm_[A-Za-z0-9]" ascii
    $s = "isSecret" ascii
  condition:
    ($g and $r and $o) and 2 of ($t1, $t2, $s)
}
