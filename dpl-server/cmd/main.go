package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/gorilla/mux"
)

const (
	defaultServerAddr = "172.16.44.80"
	defaultServerPort = "8080"
	defaultVolumePath = "/shared/loom/bluefield3-driver"
)

type CompileRequest struct {
	Target      string
	ProgramName string
}

type LoadRequest struct {
	DeviceID    string
	GrpcAddr    string
	ProgramName string
}

type DplServer struct {
	VolumePath string
	ServerAddr string
	ServerPort string
}

func main(){
	serverAddr := flag.String("listen-addr", defaultServerAddr, "IP address the server should listen on.")
	serverPort := flag.String("listen-port", defaultServerPort, "Port the server should listen on.")
	volumePath := flag.String("output", defaultVolumePath, "(Shared) Output directory for the compiled artifacts")

	flag.Parse()

	dpl := &DplServer{
		VolumePath: *volumePath,
		ServerAddr: *serverAddr,
		ServerPort: *serverPort,
	}

	router := mux.NewRouter()
	server := &http.Server{
		Addr: fmt.Sprintf("%s:%s", dpl.ServerAddr, dpl.ServerPort),
		Handler:  router,
	}
	router.HandleFunc("/dpl/compile", dpl.CompileHandler).Methods("POST")
	router.HandleFunc("/dpl/compile", dpl.LoadHandler).Methods("POST")
	go server.ListenAndServe()
}

func (dpl *DplServer) CompileHandler(res http.ResponseWriter, req *http.Request){
	var body CompileRequest

	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, 
		"dpl", "compile", 
		"--target", body.Target,
		"--out_directory", dpl.VolumePath, 
		fmt.Sprintf("%s/%s", dpl.VolumePath, body.ProgramName),
	)

	out, err := cmd.CombinedOutput(); if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}

	fmt.Printf("Compile succeeded. %s", string(out))
	fmt.Printf("Artifacts located at %s", dpl.VolumePath)

	res.Write([]byte("Compile OK."))
}	

func (dpl *DplServer) LoadHandler(res http.ResponseWriter, req *http.Request){
	var body LoadRequest

	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, 
		"dpl", "p4runtime_sh", 
		"--grpc-addr", body.GrpcAddr,
		"--device-id", body.DeviceID, 
		"--config", fmt.Sprintf("%s/%s.p4info.txt,%s/%s.dplconfig", dpl.VolumePath, body.ProgramName, dpl.VolumePath, body.ProgramName), 
	)

	out, err := cmd.CombinedOutput(); if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}

	fmt.Printf("Load succeeded. %s", string(out))
	res.Write([]byte("Load OK."))
}