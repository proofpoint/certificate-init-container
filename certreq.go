package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"path"
	"time"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/api/certificates/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	certificateSigningRequestName := fmt.Sprintf("%s-%s", podName, namespace)
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
			Request:  certificateRequestBytes,
			Usages: []certificates.KeyUsage{certificates.UsageDigitalSignature, certificates.UsageKeyEncipherment, certificates.UsageServerAuth, certificates.UsageClientAuth},
		},
	}

	_, err = client.CertificatesV1beta1().CertificateSigningRequests().Get(certificateSigningRequestName, metaV1.GetOptions{})
	if err != nil {
		_, err = client.CertificatesV1beta1().CertificateSigningRequests().Create(certificateSigningRequest)
		if err != nil {
			log.Fatalf("unable to create the certificate signing request: %s", err)
		}
		log.Println("waiting for certificate...")
	} else {
		log.Println("signing request already exists")
	}

	for {
		csr, err := client.CertificatesV1beta1().CertificateSigningRequests().Get(certificateSigningRequestName, metaV1.GetOptions{})
		if err != nil {
			log.Printf("unable to retrieve certificate signing request (%s): %s", certificateSigningRequestName, err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(csr.Status.Conditions) > 0 {
			if csr.Status.Conditions[0].Type == certificates.CertificateApproved {
				certificate = csr.Status.Certificate
				if len(certificate) > 1 {
					log.Printf("got crt %s", certificate)
					break
				} else {
					log.Printf("cert length still less than 1, wait to populate. Cert: %s", csr.Status)
				}

			}
		} else {
			log.Printf("certificate signing request (%s) not approved; trying again in 5 seconds", certificateSigningRequestName)
		}

		time.Sleep(5 * time.Second)
	}

	certFile := path.Join(certDir, "tls.crt")
	if err := ioutil.WriteFile(certFile, certificate, 0644); err != nil {
		log.Fatalf("unable to write to %s: %s", certFile, err)
	}

	log.Printf("wrote %s", certFile)

	return
}