package main

import (
	"context"
	"errors"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/gorilla/mux"
	"github.com/go-logr/logr"
)

const (
	defaultServerAddr = "172.16.44.80:8090"
	defaultNspectAddr = "172.16.44.81:9560"
	defaultAdminAddr = "172.16.44.81:9600"
)

type LoadRequest struct {
	DeviceID    string
	GrpcAddr    string
	FileName string
}

type DplServer struct {
	ServerAddr string
	NspectAddr string
	AdminAddr string
	Log        logr.Logger
}

type ErrorResponse struct {
	Message string
	Details string
}

func main(){
	serverAddr := flag.String("listen-addr", defaultServerAddr, "<IP>:<Port> the server should listen on (e.g. 10.0.0.24:8090).")
	nspectAddr := flag.String("nspect-addr", defaultNspectAddr, "<IP>:<Port> the Nspect server is reachable on (e.g. 10.0.0.25:9560).")
	adminAddr := flag.String("admin-addr", defaultAdminAddr, "<IP>:<Port> the DPL Runtime Admin server is reachable on (e.g. 10.0.0.25:9600).")

	flag.Parse()

	dpl := &DplServer{
		ServerAddr: *serverAddr,
		NspectAddr: *nspectAddr,
		AdminAddr: *adminAddr,
	}

	router := mux.NewRouter()
	server := &http.Server{
		Addr: dpl.ServerAddr,
		Handler:  router,
	}
	router.HandleFunc("/dpl/perf", dpl.PerfHandler).Methods("GET")
	router.HandleFunc("/dpl/devices", dpl.DevicesHandler).Methods("GET")

	fmt.Printf("Starting HTTP DPL server on %s\n", dpl.ServerAddr)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func (dpl *DplServer) PerfHandler(res http.ResponseWriter, _ *http.Request){
	ctx, cancel := context.WithTimeout(context.Background(), time.Second * 15)
	defer cancel()

	res.Header().Set("Content-Type", "application/json")

	data, err := dpl.runNspectCommand(ctx, "perf"); if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
		if err := json.NewEncoder(res).Encode(ErrorResponse{
			Message: "Failed to run Nspec perf command.",
			Details: fmt.Sprintf("Error: %s", err),
		}); err != nil {
			log.Printf("failed to encode error response: %v", err)
		}
		return 
	}

	res.WriteHeader(http.StatusOK)
	_, err = res.Write(data); if err != nil {
		dpl.Log.Info("Failed to write response data", "Data", data)
	}
}

func (dpl *DplServer) DevicesHandler(res http.ResponseWriter, _ *http.Request){
	ctx, cancel := context.WithTimeout(context.Background(), time.Second * 10)
	defer cancel()

	res.Header().Set("Content-Type", "application/json")

	data, err := dpl.runNspectCommand(ctx, "devices"); if err != nil {
		res.WriteHeader(http.StatusInternalServerError)
		if err := json.NewEncoder(res).Encode(ErrorResponse{
			Message: "Failed to run Nspec devices command.",
			Details: fmt.Sprintf("Error: %s", err),
		}); err != nil {
			fmt.Printf("failed to encode error response: %v", err)
		}
		return 
	}

	res.WriteHeader(http.StatusOK)
	_, err = res.Write(data); if err != nil {
		fmt.Printf("Failed to write response data %s", data)
	}
}

func (dpl *DplServer) runNspectCommand(ctx context.Context, command string) ([]byte, error) {

	cmd := exec.CommandContext(ctx, 
		"dpl", "nspect",
		"-a", dpl.NspectAddr,
		command, "--json", 
	)

	dpl.Log.Info("Running perf command: dpl nspect -a <IP>:<Port> --json ", command)
	fmt.Printf("Running nspect command: %s", cmd.String())

	out, err := cmd.CombinedOutput(); if err != nil {
		fmt.Printf("Error running perf command %s. Out: %s", err, string(out))
		return out, fmt.Errorf("Nspec command %s produced error %w", command, err)
	}

	return out, nil
}

/* func (dpl *DplServer) CompileHandler(res http.ResponseWriter, req *http.Request){
	var body CompileRequest

	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	programName := strings.TrimSuffix(body.FileName, filepath.Ext(body.FileName))
	dir := filepath.Join(dpl.VolumePath, programName)

	cmd := exec.CommandContext(ctx, 
		"dpl", "compile", 
		"--target", body.Target,
		"--odir", dir, 
		filepath.Join(dir, body.FileName),
	)

	fmt.Println("executing compile command: ", cmd.String())

	out, err := cmd.CombinedOutput(); if err != nil {
		fmt.Println("when compiling", err)
		fmt.Println("Output", string(out))
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Compile succeeded. %s\n", string(out))
	fmt.Printf("Artifacts located at %s.\n", dir)

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

	programName := strings.TrimSuffix(body.FileName, filepath.Ext(body.FileName))
	dir := filepath.Join(dpl.VolumePath, programName)

	cmd := exec.CommandContext(ctx, 
		"dpl", "p4runtime_sh", 
		"--grpc-addr", body.GrpcAddr,
		"--device-id", body.DeviceID, 
		"--config", fmt.Sprintf("%s/%s.p4info.txt,%s/%s.dplconfig", dir, programName, dir, programName), 
	)

	out, err := cmd.CombinedOutput(); if err != nil {
		fmt.Println("when loading", err)
		fmt.Println("Output", string(out))
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Load succeeded. %s\n", string(out))
	res.Write([]byte("Load OK."))
} */