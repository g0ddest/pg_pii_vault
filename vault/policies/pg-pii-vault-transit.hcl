# key_mode = 'transit': Vault performs the encryption; keys never leave Vault.
path "transit/encrypt/+" {
  capabilities = ["update"]
}
path "transit/decrypt/+" {
  capabilities = ["update"]
}
path "transit/keys/+" {
  # Create non-exportable keys on first encryption ("update": no existence check).
  capabilities = ["update"]
  allowed_parameters = {
    "type" = ["aes256-gcm96"]
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
