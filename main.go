package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

type moduleSignature struct {
	Algo      byte
	Hash      byte
	IDType    byte
	SignerLen byte
	KeyIDLen  byte
	_         [3]byte
	SigLen    uint32
}

const (
	moduleSignatureLen = 12
	PKEY_ID_PKCS7      = 2
	magicNumber        = "~Module signature appended~\n"
)

func usage() {
	fmt.Printf(`Usage: unsign-file [-f] module-file

Remove the signature from the input kernel module-file and write the
result to a new file with the added extension ".nosig". The output
file is not overwritten if it exists. The module-file was typically
signed using the kernel tool scripts/sign-file.

This tool exists because a common way of removing such signature is
by using strip(1), but that also alters the module in other ways.

  -f  overwrite the output file if it exists
`)
}

func main() {
	forceOverwrite := false
	args := os.Args[1:]

	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	if len(args) > 0 {
		if args[0] == "-f" {
			forceOverwrite = true
			args = args[1:]
		}
	}

	if len(args) != 1 {
		fmt.Printf("Expected exactly 1 module file\n\n")
		usage()
		os.Exit(1)
	}

	inFile := args[0]

	data, err := os.ReadFile(inFile)
	if err != nil {
		fmt.Printf("ReadFile failed: %s\n", err)
		os.Exit(1)
	}

	if !bytes.HasSuffix(data, []byte(magicNumber)) {
		fmt.Printf("File is not a signed module, it does not end with %q\n", magicNumber)
		os.Exit(1)
	}

	var modSigInfo moduleSignature

	r := bytes.NewReader(data[len(data)-(moduleSignatureLen+len(magicNumber)):])
	if err := binary.Read(r, binary.BigEndian, &modSigInfo); err != nil {
		fmt.Printf("binary.Read failed: %s\n", err)
		os.Exit(1)
	}

	// Check expected values according to sign-file.c
	if modSigInfo.Algo != 0 ||
		modSigInfo.Hash != 0 ||
		modSigInfo.IDType != PKEY_ID_PKCS7 ||
		modSigInfo.SignerLen != 0 ||
		modSigInfo.KeyIDLen != 0 {
		fmt.Printf("File is probably not a signed module, ModuleSignature fields has unexpected contents\n")
		os.Exit(1)
	}

	moduleLen := len(data) - (int(modSigInfo.SigLen) + moduleSignatureLen + len(magicNumber))

	if moduleLen < 0 {
		fmt.Printf("File is not a correctly signed module, calculated module size is %d bytes\n", moduleLen)
		os.Exit(1)
	}

	outFile := fmt.Sprintf("%s.nosig", inFile)

	if !forceOverwrite {
		if _, err := os.Stat(outFile); err == nil {
			fmt.Printf("%s already exists\n", outFile)
			os.Exit(1)
		} else if !os.IsNotExist(err) {
			fmt.Printf("Stat(%s) failed: %s\n", outFile, err)
			os.Exit(1)
		}
	}

	if err := os.WriteFile(outFile, data[:moduleLen], 0o600); err != nil {
		fmt.Printf("WriteFile failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %s\n", outFile)
}
