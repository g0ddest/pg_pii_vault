# Normal operation: export key material, create keys on first encryption.
path "transit/export/encryption-key/+" {
  capabilities = ["read"]
}
path "transit/keys/+" {
  # Creating a Transit key is an "update" (the path has no existence check).
  # "+" matches the key name only, so rotate/config/trim stay forbidden.
  capabilities = ["update"]
  allowed_parameters = {
    "type"       = ["aes256-gcm96"]
    "exportable" = [true]
  }
}
# Lets Vault Agent keep a periodic token alive. Vault's "default" policy
# grants the same; the rule matters when that policy is not attached.
path "auth/token/renew-self" {
  capabilities = ["update"]
}
# Optional: lets piitext_vault_check() inspect the token and its policy.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "sys/capabilities-self" {
  capabilities = ["update"]
}
