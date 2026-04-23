package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type VmList struct {
	Ids map[string]struct {
		Node string `json:"node"`
		Type string `json:"type"`
	} `json:"ids"`
}

func main() {
	allowedIDStr := flag.String("spiffeid", "", "The client SPIFFE ID allowed to connect")
	port := flag.String("port", "9443", "HTTPS port to listen on")
	domain := flag.String("domain", "", "Domain to append to node names for FQDN (e.g. 'example.com')")
	flag.Parse()

	if *allowedIDStr == "" {
		log.Fatal("--spiffeid is required")
	}

	allowedID, err := spiffeid.FromString(*allowedIDStr)
	if err != nil {
		log.Fatalf("Invalid SPIFFE ID: %v", err)
	}

	ctx := context.Background()

	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("Unable to create X509 source: %v", err)
	}
	defer source.Close()

	authorizer := tlsconfig.AuthorizeID(allowedID)

	tlsConfig := tlsconfig.MTLSServerConfig(source, source, authorizer)

	r := mux.NewRouter()
	r.HandleFunc("/ek-cert/{vmid}/{uuid}", handleGetEKCert).Methods("GET")
	r.HandleFunc("/vm-metadata/{vmid}", handleVMMetadata).Methods("GET")
	r.HandleFunc("/vm-to-node/{vmid}", func(w http.ResponseWriter, r *http.Request) {
		handleIDToNode(w, r, *domain)
	}).Methods("GET")

	log.Printf("Getting cert from spiffe\n")
	listener, err := tls.Listen("tcp", ":"+*port, tlsConfig)
	if err != nil {
		log.Fatalf("Unable to create TLS listener: %v", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler: r,
	}

	log.Printf("Server starting on :%s, domain: %s", *port, *domain)

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleIDToNode(w http.ResponseWriter, r *http.Request, domain string) {
	vars := mux.Vars(r)
	vmid := vars["vmid"]
	if idInt, err := strconv.ParseInt(vmid, 10, 32); err != nil {
		http.Error(w, "VM ID invalid", http.StatusBadRequest)
		return
	} else {
		vmid = strconv.FormatInt(idInt, 10)
	}

	data, err := os.ReadFile("/etc/pve/.vmlist")
	if err != nil {
		log.Printf("Error reading .vmlist: %v", err)
		http.Error(w, "Internal cluster error", http.StatusInternalServerError)
		return
	}

	var vmlist VmList
	if err := json.Unmarshal(data, &vmlist); err != nil {
		log.Printf("Error unmarshaling .vmlist: %v", err)
		http.Error(w, "Internal cluster error", http.StatusInternalServerError)
		return
	}

	vmInfo, exists := vmlist.Ids[vmid]
	if !exists {
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}

	nodeName := vmInfo.Node

	if domain != "" && !strings.Contains(nodeName, ".") {
		nodeName = fmt.Sprintf("%s.%s", nodeName, strings.TrimPrefix(domain, "."))
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, nodeName)
}

func handleGetEKCert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	vmid := vars["vmid"]
	providedUUID := vars["uuid"]

	if idInt, err := strconv.ParseInt(vmid, 10, 32); err != nil {
		http.Error(w, "VM ID invalid", http.StatusBadRequest)
		return
	} else {
		vmid = strconv.FormatInt(idInt, 10)
	}

	uuidPath := filepath.Join("/var/lib/swtpm", vmid, "uuid")
	ekPath := filepath.Join("/var/lib/swtpm", vmid, "ek.pem")

	storedUUID, err := os.ReadFile(uuidPath)
	if err != nil {
		http.Error(w, "VM ID not found", http.StatusNotFound)
		return
	}

	if strings.TrimSpace(string(storedUUID)) != providedUUID {
		http.Error(w, "UUID mismatch", http.StatusForbidden)
		return
	}

	ekData, err := os.ReadFile(ekPath)
	if err != nil {
		http.Error(w, "EK certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(ekData)
}

func handleVMMetadata(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	vmid := vars["vmid"]

	if _, err := strconv.Atoi(vmid); err != nil {
		http.Error(w, "Invalid VM ID", http.StatusBadRequest)
		return
	}

	apiPath := fmt.Sprintf("/nodes/localhost/qemu/%s/config", vmid)
	cmd := exec.Command("pvesh", "get", apiPath, "--output-format", "json")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		errStr := stderr.String()
		if strings.Contains(errStr, "404") || strings.Contains(errStr, "not found") {
			log.Printf("VM %s not found on this node", vmid)
			http.Error(w, "VM not found on this node", http.StatusNotFound)
			return
		}

		log.Printf("pvesh execution error: %v, stderr: %s", err, errStr)
		http.Error(w, "Internal server error calling pvesh", http.StatusInternalServerError)
		return
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &metadata); err != nil {
		log.Printf("JSON unmarshal error: %v", err)
		http.Error(w, "Internal error processing metadata", http.StatusInternalServerError)
		return
	}

	for key := range metadata {
		k := strings.ToLower(key)
		if strings.HasPrefix(k, "ci") ||
			strings.HasPrefix(k, "ipconfig") ||
			k == "sshkeys" ||
			k == "searchdomain" ||
			k == "nameserver" ||
			k == "cipassword" {
			delete(metadata, key)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}
