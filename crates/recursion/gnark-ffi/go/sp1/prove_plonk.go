package sp1

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// logStderr writes directly to fd 2 via raw syscall, bypassing all Go
// buffering. This is needed because fmt.Printf, fmt.Fprintf(os.Stderr, ...),
// and log.Printf are all invisible when Go is compiled as a c-archive and
// linked into a Rust binary running in Docker.
func logStderr(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	syscall.Write(2, []byte(msg))
}

var globalPlonkMutex sync.RWMutex
var globalPlonkScs constraint.ConstraintSystem = plonk.NewCS(ecc.BN254)
var globalPlonkScsInitialized = false
var globalPlonkPk plonk.ProvingKey = plonk.NewProvingKey(ecc.BN254)
var globalPlonkPkInitialized = false
var globalPlonkVk plonk.VerifyingKey = plonk.NewVerifyingKey(ecc.BN254)
var globalPlonkVkInitialized = false

func ProvePlonk(dataDir string, witnessPath string) Proof {
	// Sanity check the required arguments have been provided.
	if dataDir == "" {
		panic("dataDirStr is required")
	}

	logStderr("plonk: ProvePlonk called, dataDir=%s\n", dataDir)
	start := time.Now()
	os.Setenv("CONSTRAINTS_JSON", dataDir+"/"+constraintsJsonFile)
	logStderr("plonk: Setting environment variables took %s\n", time.Since(start))

	// Read the R1CS (cached globally after first call).
	globalPlonkMutex.Lock()
	if !globalPlonkScsInitialized {
		start = time.Now()
		scsFile, err := os.Open(dataDir + "/" + plonkCircuitPath)
		if err != nil {
			panic(err)
		}
		scsReader := bufio.NewReaderSize(scsFile, 1024*1024)
		globalPlonkScs.ReadFrom(scsReader)
		defer scsFile.Close()
		globalPlonkScsInitialized = true
		logStderr("plonk: Reading circuit (first call) took %s\n", time.Since(start))
	} else {
		logStderr("plonk: Using cached circuit\n")
	}
	globalPlonkMutex.Unlock()

	// Read the proving key (cached globally after first call).
	globalPlonkMutex.Lock()
	if !globalPlonkPkInitialized {
		start = time.Now()
		pkFile, err := os.Open(dataDir + "/" + plonkPkPath)
		if err != nil {
			panic(err)
		}
		pkReader := bufio.NewReaderSize(pkFile, 1024*1024)
		globalPlonkPk.UnsafeReadFrom(pkReader)
		defer pkFile.Close()
		globalPlonkPkInitialized = true
		logStderr("plonk: Reading proving key (first call) took %s\n", time.Since(start))
	} else {
		logStderr("plonk: Using cached proving key\n")
	}
	globalPlonkMutex.Unlock()

	// Read the verifier key (cached globally after first call).
	globalPlonkMutex.Lock()
	if !globalPlonkVkInitialized {
		start = time.Now()
		vkFile, err := os.Open(dataDir + "/" + plonkVkPath)
		if err != nil {
			panic(err)
		}
		globalPlonkVk.ReadFrom(vkFile)
		defer vkFile.Close()
		globalPlonkVkInitialized = true
		logStderr("plonk: Reading verifying key (first call) took %s\n", time.Since(start))
	} else {
		logStderr("plonk: Using cached verifying key\n")
	}
	globalPlonkMutex.Unlock()

	start = time.Now()
	// Read the witness file.
	data, err := os.ReadFile(witnessPath)
	if err != nil {
		panic(err)
	}
	logStderr("plonk: Reading witness file took %s\n", time.Since(start))

	start = time.Now()
	// Deserialize the JSON data into a slice of Instruction structs
	var witnessInput WitnessInput
	err = json.Unmarshal(data, &witnessInput)
	if err != nil {
		panic(err)
	}
	logStderr("plonk: Deserializing JSON data took %s\n", time.Since(start))

	start = time.Now()
	// Generate the witness.
	assignment := NewCircuit(witnessInput)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	logStderr("plonk: Generating witness took %s\n", time.Since(start))

	logStderr("plonk: Starting plonk.Prove() (constraint solver + FFT + KZG commitments)...\n")
	start = time.Now()
	// Generate the proof.
	proof, err := plonk.Prove(globalPlonkScs, globalPlonkPk, witness)
	if err != nil {
		logStderr("plonk: Error: %v\n", err)
		panic(err)
	}
	logStderr("plonk: Generating proof took %s\n", time.Since(start))

	logStderr("plonk: Starting plonk.Verify()...\n")
	start = time.Now()
	// Verify proof.
	err = plonk.Verify(proof, globalPlonkVk, publicWitness)
	if err != nil {
		panic(err)
	}
	logStderr("plonk: Verifying proof took %s\n", time.Since(start))

	logStderr("plonk: Building SP1 proof response...\n")
	start = time.Now()
	result := NewSP1PlonkBn254Proof(&proof, witnessInput)
	logStderr("plonk: Building response took %s\n", time.Since(start))

	return result
}
