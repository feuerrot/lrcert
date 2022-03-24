package main

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"os"
)

const ctoOID = "1.3.6.1.4.1.311.21.7"

type CertificateTemplateOID struct {
	TemplateID           asn1.ObjectIdentifier
	TemplateMajorVersion int32
	TemplateMinorVersion int32
}

func (c *CertificateTemplateOID) String() string {
	return fmt.Sprintf("OID: %s (%d/%d)", c.TemplateID.String(), c.TemplateMajorVersion, c.TemplateMinorVersion)
}

func getCertificateTemplateOID(filename string) (CertificateTemplateOID, error) {
	var cto CertificateTemplateOID

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return cto, err
	}

	crt, err := x509.ParseCertificate(raw)
	if err != nil {
		return cto, err
	}

	for _, ext := range crt.Extensions {
		if ext.Id.String() == ctoOID {
			_, err = asn1.Unmarshal(ext.Value, &cto)
			if err != nil {
				return cto, fmt.Errorf("couldn't unmarshal extension value: %v", err)
			}

			return cto, nil
		}
	}

	return cto, fmt.Errorf("couldn't find extension %s", ctoOID)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s [certfile]", os.Args[0])
	}

	cto, err := getCertificateTemplateOID(os.Args[1])
	if err != nil {
		log.Fatalf("couldn't get CTOID: %v", err)
	}

	log.Println(cto.String())
}
