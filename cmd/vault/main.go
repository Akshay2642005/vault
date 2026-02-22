package main

import (
	"vault/internal/cli"
	_ "vault/internal/storage/postgres"
	_ "vault/internal/storage/sqlite"
)

func main() {
	cli.Execute()
}
