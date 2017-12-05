// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	certificates "github.com/ericchiang/k8s/apis/certificates/v1beta1"

	"github.com/ericchiang/k8s"
	"github.com/ericchiang/k8s/apis/meta/v1"
)

var (
	additionalDNSNames string
	certDir            string
	clusterDomain      string
	hostname           string
	namespace          string
	podIP              string
	podName            string
	serviceIPs         string
	serviceNames       string
	subdomain          string
	labels             string
	secretName         string
	createSecret       bool
	keysize            int
)

func main() {
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&certDir, "cert-dir", "/etc/tls", "The directory where the TLS certs should be written")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&hostname, "hostname", "", "hostname as defined by pod.spec.hostname")
	flag.StringVar(&namespace, "namespace", "default", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&podName, "pod-name", "", "name as defined by pod.metadata.name")
	flag.StringVar(&podIP, "pod-ip", "", "IP address as defined by pod.status.podIP")
	flag.StringVar(&serviceNames, "service-names", "", "service names that resolve to this Pod; comma separated")
	flag.StringVar(&serviceIPs, "service-ips", "", "service IP addresses that resolve to this Pod; comma separated")
	flag.StringVar(&subdomain, "subdomain", "", "subdomain as defined by pod.spec.subdomain")
	flag.StringVar(&labels, "labels", "", "labels to include in CertificateSigningRequest object; comma seprated list of key=value")
	flag.StringVar(&secretName, "secret-name", "", "secret name to store generated files")
	flag.BoolVar(&createSecret, "create-secret", false, "create a new secret instead of waiting for one to update")
	flag.IntVar(&keysize, "keysize", 3072, "bit size of private key")
	flag.Parse()

	client, err := k8s.NewInClusterClient()
	if err != nil {
		log.Fatalf("unable to create a Kubernetes client: %s", err)
	}

	// Gather the list of labels that will be added to the CreateCertificateSigningRequest object
	labelsMap := make(map[string]string)

	for _, n := range strings.Split(labels, ",") {
		if n == "" {
			continue
		}
		s := strings.Split(n, "=")
		label, key := s[0], s[1]
		if label == "" {
			continue
		}
		labelsMap[label] = key
	}

	// Gather the list of IP addresses for the certificate's IP SANs field which
	// include:
	//   - the pod IP address
	//   - each service IP address that maps to this pod
	ip := net.ParseIP(podIP)
	if ip.To4() == nil && ip.To16() == nil {
		log.Fatal("invalid pod IP address")
	}

	ipaddresses := []net.IP{ip}

	for _, s := range strings.Split(serviceIPs, ",") {
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip.To4() == nil && ip.To16() == nil {
			log.Fatal("invalid service IP address")
		}
		ipaddresses = append(ipaddresses, ip)
	}

	// Gather a list of DNS names that resolve to this pod which include the
	// default DNS name:
	//   - ${pod-ip-address}.${namespace}.pod.${cluster-domain}
	//
	// For each service that maps to this pod a dns name will be added using
	// the following template:
	//   - ${service-name}.${namespace}.svc.${cluster-domain}
	//
	// A dns name will be added for each additional DNS name provided via the
	// `-additional-dnsnames` flag.
	dnsNames := defaultDNSNames(podIP, hostname, subdomain, namespace, clusterDomain)

	for _, n := range strings.Split(additionalDNSNames, ",") {
		if n == "" {
			continue
		}
		dnsNames = append(dnsNames, n)
	}

	for _, n := range strings.Split(serviceNames, ",") {
		if n == "" {
			continue
		}
		dnsNames = append(dnsNames, serviceDomainName(n, namespace, clusterDomain))
	}

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
		IPAddresses:        ipaddresses,
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
		Metadata: &v1.ObjectMeta{
			Name:   k8s.String(certificateSigningRequestName),
			Labels: labelsMap,
		},
		Spec: &certificates.CertificateSigningRequestSpec{
			Groups:   []string{"system:authenticated"},
			Request:  certificateRequestBytes,
			KeyUsage: []string{"digital signature", "key encipherment", "server auth", "client auth"},
		},
	}

	log.Printf("Deleting certificate signing request  %s", certificateSigningRequestName)
	client.CertificatesV1Beta1().DeleteCertificateSigningRequest(context.Background(), certificateSigningRequestName)
	log.Printf("Removed approved request %s", certificateSigningRequestName)

	_, err = client.CertificatesV1Beta1().GetCertificateSigningRequest(context.Background(), certificateSigningRequestName)
	if err != nil {
		_, err = client.CertificatesV1Beta1().CreateCertificateSigningRequest(context.Background(), certificateSigningRequest)
		if err != nil {
			log.Fatalf("unable to create the certificate signing request: %s", err)
		}
		log.Println("waiting for certificate...")
	} else {
		log.Println("signing request already exists")
	}

	var certificate []byte
	for {
		csr, err := client.CertificatesV1Beta1().GetCertificateSigningRequest(context.Background(), certificateSigningRequestName)
		if err != nil {
			log.Printf("unable to retrieve certificate signing request (%s): %s", certificateSigningRequestName, err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(csr.GetStatus().GetConditions()) > 0 {
			if *csr.GetStatus().GetConditions()[0].Type == "Approved" {
				certificate = csr.GetStatus().Certificate
				if len(certificate) > 1 {
					log.Printf("got crt %s", certificate)
					break
				} else {
					log.Printf("cert length still less than 1, wait to populate. Cert: %s", csr.GetStatus())
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

	writeKeystore(certDir, key, certificate)

	log.Printf("Deleting certificate signing request %s", certificateSigningRequestName)
	client.CertificatesV1Beta1().DeleteCertificateSigningRequest(context.Background(), certificateSigningRequestName)
	log.Printf("Removed approved request %s", certificateSigningRequestName)

	if secretName != "" {
		for {
			ks, err := client.CoreV1().GetSecret(context.Background(), secretName, namespace)
			if err != nil {
				if createSecret {
					log.Fatalf("TODO: cannot create secrets")
				} else {
					log.Printf("Secret to store credentials (%s) not found; trying again in 5 seconds", secretName)
					time.Sleep(5 * time.Second)
					continue
				}
			}

			k8sCrt, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

			stringData := make(map[string]string)
			stringData["tls.key"] = string(pemKeyBytes)
			stringData["tls.crt"] = string(certificate)
			stringData["k8s.crt"] = string(k8sCrt)                                    // ok
			stringData["tlsAndK8s.crt"] = string(certificate) + "\n" + string(k8sCrt) // ok

			ks.StringData = stringData
			_, err = client.CoreV1().UpdateSecret(context.TODO(), ks)
			log.Printf("Stored credentials in secret: (%s)", secretName)

			break
		}
	}

	os.Exit(0)
}

func defaultDNSNames(ip, hostname, subdomain, namespace, clusterDomain string) []string {
	ns := []string{podDomainName(ip, namespace, clusterDomain)}
	if hostname != "" && subdomain != "" {
		ns = append(ns, podHeadlessDomainName(hostname, subdomain, namespace, clusterDomain))
	}
	return ns
}

func serviceDomainName(name, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
}

func podDomainName(ip, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.pod.%s", strings.Replace(ip, ".", "-", -1), namespace, domain)
}

func podHeadlessDomainName(hostname, subdomain, namespace, domain string) string {
	if hostname == "" || subdomain == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.svc.%s", hostname, subdomain, namespace, domain)
}
