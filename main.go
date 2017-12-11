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
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	flag.StringVar(&namespace, "namespace", "", "namespace as defined by pod.metadata.namespace")
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

	if namespace == "" {
		os.Stderr.WriteString("missing required -namespace argument/flag\n")
		os.Exit(2)
	}
	if podName == "" {
		os.Stderr.WriteString("missing required -pod-name argument/flag\n")
		os.Exit(2)
	}

	// Create a Kubernetes client.
	// Initialize a configuration based on the default service account.
    client, err := newClient()
	if err != nil {
		log.Fatalf("Could not create Kubernetes client: %s", err)
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

	ipAddresses := []net.IP{ip}

	for _, s := range strings.Split(serviceIPs, ",") {
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip.To4() == nil && ip.To16() == nil {
			log.Fatal("invalid service IP address")
		}
		ipAddresses = append(ipAddresses, ip)
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

	key, certificate := requestCertificate(client, labelsMap, dnsNames, ipAddresses)

	writeKeystore(certDir, key, certificate)

	if secretName != "" {
		pemKeyBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		for {
			ks, err := client.CoreV1().Secrets(namespace).Get(secretName, metaV1.GetOptions{})
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
			_, err = client.CoreV1().Secrets(namespace).Update(ks)
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

func newClient() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
		// Initialize a configuration based on the default service account.
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}

	return kubernetes.NewForConfig(config)
}
