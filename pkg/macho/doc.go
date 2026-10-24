// Package macho implements checksec's Mach-O hardening checks. Every check has
// the signature func(*macho.File) *checksec.Result so pkg/utils can register
// it next to the ELF checks in pkg/checksec.
package macho
