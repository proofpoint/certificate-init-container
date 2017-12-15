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
	"flag"
	"fmt"
	"github.com/proofpoint/kapprover/podnames"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net"
	"os"
	"strings"
)

var (
	namespace          string
	podName            string
	queryK8s           bool
	additionalDNSNames string
	certDir            string
	clusterDomain      string
	serviceIPs         string
	serviceNames       string
	labels             string
	keysize            int
)

func main() {
	flag.StringVar(&namespace, "namespace", "", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&podName, "pod-name", "", "name as defined by pod.metadata.name")
	flag.BoolVar(&queryK8s, "query-k8s", false, "query Kubernetes for names appropriate to this Pod")
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&certDir, "cert-dir", "/etc/tls", "The directory where the TLS certs should be written")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&serviceNames, "service-names", "", "service names that resolve to this Pod; comma separated")
	flag.StringVar(&serviceIPs, "service-ips", "", "service IP addresses that resolve to this Pod; comma separated")
	flag.StringVar(&labels, "labels", "", "labels to include in CertificateSigningRequest object; comma seprated list of key=value")
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

	var ipAddresses []net.IP
	var dnsNames []string

	if queryK8s {
		pod, err := client.CoreV1().Pods(namespace).Get(podName, metaV1.GetOptions{})
		if err != nil {
			log.Fatalf("Could not query pod %q in namespace %q: %s", podName, namespace, err)
		}

		dnsNames, ipAddresses, err = podnames.GetNamesForPod(client, *pod, clusterDomain)
		if err != nil {
			log.Fatalf("Could not query names for pod %q in namespace %q: %s", podName, namespace, err)
		}
	}

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

	os.Exit(0)
}

func serviceDomainName(name, namespace, domain string) string {
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain)
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
