# Only if piitext_shred() is used from the database.
path "transit/keys/+/config" {
  capabilities = ["update"]
  allowed_parameters = {
    "deletion_allowed" = [true]
  }
}
path "transit/keys/+" {
  capabilities = ["delete"]
}
