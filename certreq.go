package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
	"math/big"
	"net"
	"path"
	"time"
)

const (
	randAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
)

var (
	randAlphabetLength = big.NewInt(int64(len(randAlphabet)))
)

func requestCertificate(client kubernetes.Interface, labels map[string]string, dnsNames []string, ipAddresses []net.IP) (key *rsa.PrivateKey, certificate []byte) {
	// Generate a private key, pem encode it, and save it to the filesystem.
	// The private key will be used to create a certificate signing request (csr)
	// that will be submitted to a Kubernetes CA to obtain a TLS certificate.
	key, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		log.Fatalf("unable to genarate the private key: %s", err)
	}

	pemKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	keyFile := path.Join(certDir, "tls.key")
	if err := ioutil.WriteFile(keyFile, pemKeyBytes, 0644); err != nil {
		log.Fatalf("unable to write to %s: %s", keyFile, err)
	}

	log.Printf("wrote %s", keyFile)

	// Generate the certificate request, pem encode it, and save it to the filesystem.
	certificateRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
	}

	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, key)
	if err != nil {
		log.Fatalf("unable to generate the certificate request: %s", err)
	}

	certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certificateRequest})

	csrFile := path.Join(certDir, "tls.csr")
	if err := ioutil.WriteFile(csrFile, certificateRequestBytes, 0644); err != nil {
		log.Fatalf("unable to %s, error: %s", csrFile, err)
	}

	log.Printf("wrote %s", csrFile)

	// Submit a certificate signing request, wait for it to be approved, then save
	// the signed certificate to the file system.
	certificateSigningRequestName := requestName()
	certificateSigningRequest := &certificates.CertificateSigningRequest{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "CertificateSigningRequest",
			APIVersion: "v1beta1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:   certificateSigningRequestName,
			Labels: labels,
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Request: certificateRequestBytes,
			Usages:  []certificates.KeyUsage{certificates.UsageDigitalSignature, certificates.UsageKeyEncipherment, certificates.UsageServerAuth, certificates.UsageClientAuth},
		},
	}

	_, err = client.CertificatesV1beta1().CertificateSigningRequests().Get(context.TODO(), certificateSigningRequestName, metaV1.GetOptions{})
	if err != nil {
		_, err = client.CertificatesV1beta1().CertificateSigningRequests().Create(context.TODO(), certificateSigningRequest, metaV1.CreateOptions{})
		if err != nil {
			log.Fatalf("unable to create the certificate signing request: %s", err)
		}
		log.Println("waiting for certificate...")
	} else {
		log.Println("signing request already exists")
	}

	for {
		csr, err := client.CertificatesV1beta1().CertificateSigningRequests().Get(context.TODO(), certificateSigningRequestName, metaV1.GetOptions{})
		if errors.IsNotFound(err) {
			// If the request got deleted, waiting won't help.
			log.Fatalf("certificate signing request (%s) not found", certificateSigningRequestName)
		}
		if err != nil {
			log.Printf("unable to retrieve certificate signing request (%s): %s", certificateSigningRequestName, err)
			time.Sleep(5 * time.Second)
			continue
		}

		certificate = csr.Status.Certificate
		if len(certificate) > 0 {
			log.Printf("got certificate:\n%s", certificate)
			break
		}

		for _, condition := range csr.Status.Conditions {
			if condition.Type == certificates.CertificateDenied {
				log.Fatalf("certificate signing request (%s) denied for %q: %q", certificateSigningRequestName, condition.Reason, condition.Message)
			}
		}

		log.Printf("certificate signing request (%s) not issued; trying again in 5 seconds", certificateSigningRequestName)
		time.Sleep(5 * time.Second)
	}

	certFile := path.Join(certDir, "tls.crt")
	if err := ioutil.WriteFile(certFile, certificate, 0644); err != nil {
		log.Fatalf("unable to write to %s: %s", certFile, err)
	}

	log.Printf("wrote %s", certFile)

	return
}

func requestName() (name string) {
	name = fmt.Sprintf("%s-%s-", podName, namespace)
	for i := 0; i < 5; i++ {
		n, err := rand.Int(rand.Reader, randAlphabetLength)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate request name: %v", err))
		}
		name += string(randAlphabet[n.Int64()])
	}
	return
}
