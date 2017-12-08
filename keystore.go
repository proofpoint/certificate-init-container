package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/lwithers/minijks/jks"
	"io/ioutil"
	"log"
	"path"
	"time"
)

func writeKeystore(certDir string, privkey *rsa.PrivateKey, pemCertificate []byte) {
	var certChain []*jks.KeypairCert
	for {
		var block *pem.Block
		block, pemCertificate = pem.Decode(pemCertificate)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate: %v", err)
		}
		certChain = append(certChain, &jks.KeypairCert{Cert: cert})
	}

	if len(certChain) == 0 {
		log.Fatalf("Certificate chain has no certificates")
	}
	key, ok := certChain[0].Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Certificate public key algorithm is not RSA")
	}
	if key.N.Cmp(privkey.N) != 0 || key.E != privkey.E {
		log.Fatalf("Certificate public key does not match our private key")
	}

	kp := jks.Keypair{
		Alias:      "host",
		Timestamp:  time.Now(),
		PrivateKey: privkey,
		CertChain:  certChain,
	}

	ks := jks.Keystore{
		Keypairs: []*jks.Keypair{&kp},
	}

	keystoreBytes, err := ks.Pack(&jks.Options{Password: "keystore"})
	if err != nil {
		log.Fatalf("Failed to create keystore: %v", err)
	}

	keystoreFile := path.Join(certDir, "tls.jks")
	if err := ioutil.WriteFile(keystoreFile, keystoreBytes, 0644); err != nil {
		log.Fatalf("unable to write %s, error: %v", keystoreFile, err)
	}
	log.Printf("wrote %s", keystoreFile)
}
