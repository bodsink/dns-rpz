package db

import _ "embed"

// Schema contains the SQL schema for the DNS-RPZ database.
//
//go:embed schema.sql
var Schema string
