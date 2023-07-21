package main

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	configDir := kingpin.Flag("config.dir", "Config dir path.").Required().ExistingDir()
	configNames := kingpin.Flag("config.names", "Comma separated names of configs to load.").Required().String()
	debug := kingpin.Flag("debug", "Enable debug.").Bool()
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(":9435").String()
	metricsPath := kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	kingpin.Version(version.Print("ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	libbpfgoCallbacks := libbpfgo.Callbacks{Log: libbpfLogCallback}
	if !*debug {
		libbpfgoCallbacks.LogFilters = append(libbpfgoCallbacks.LogFilters, func(libLevel int, msg string) bool {
			return libLevel == libbpfgo.LibbpfDebugLevel
		})
	}

	libbpfgo.SetLoggerCbs(libbpfgoCallbacks)

	started := time.Now()

	configs, err := config.ParseConfigs(*configDir, strings.Split(*configNames, ","))
	if err != nil {
		log.Fatalf("Error parsing configs: %v", err)
	}

	// // define an empty list of PIDs
	// var pids []uint32

	// // if containerIds is not empty, then we need to get the PID of the container
	// if *containerIds != "" {
	// 	// Create a Docker client.
	// 	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	// 	if err != nil {
	// 		panic(err.Error())
	// 	}

	// 	// parse comma separated container ids into a list
	// 	containerIDs := strings.Split(*containerIds, ",")
	// 	// iterate over containers
	// 	for _, containerID := range containerIDs {
	// 		// skip if container id does not have prefix "docker://"
	// 		if !strings.HasPrefix(containerID, "docker://") {
	// 			fmt.Printf("Container ID %s does not have prefix 'docker://', skipping\n", containerID)
	// 			continue
	// 		}
	// 		// Remove the "docker://" prefix from the container id
	// 		containerID = strings.TrimPrefix(containerID, "docker://")
	// 		containerJSON, err := dockerClient.ContainerInspect(context.Background(), containerID)
	// 		if err != nil {
	// 			panic(err.Error())
	// 		}
	// 		// The PID is stored in the State.Pid field of the container details.
	// 		fmt.Printf("PID for container %s: %d\n", containerID, containerJSON.State.Pid)
	// 		// append the PID to the list of PIDs
	// 		pids = append(pids, uint32(containerJSON.State.Pid))
	// 	}
	// 	// log warning if no PIDs were found
	// 	if len(pids) == 0 {
	// 		log.Printf("No PIDs found for container IDs %s", *containerIds)

	// 		// remove from configs any programs that support container IDs but no PIDs were found
	// 		newConfigs := []config.Config{}
	// 		for _, config := range configs {
	// 			if config.SupportsContainerIDs {
	// 				log.Printf("Removing config %s because it container IDs were provided but no PIDs were found", config.Name)
	// 			} else {
	// 				newConfigs = append(newConfigs, config)
	// 			}
	// 		}
	// 		configs = newConfigs
	// 	}
	// 	for _, config := range configs {
	// 		config.PIDs = pids
	// 	}
	// }

	e, err := exporter.New(configs)
	if err != nil {
		log.Fatalf("Error creating exporter: %s", err)
	}

	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	log.Printf("Started with %d programs found in the config in %dms", len(configs), time.Since(started).Milliseconds())

	err = prometheus.Register(version.NewCollector("ebpf_exporter"))
	if err != nil {
		log.Fatalf("Error registering version collector: %s", err)
	}

	err = prometheus.Register(e)
	if err != nil {
		log.Fatalf("Error registering exporter: %s", err)
	}

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte(`<html>
			<head><title>eBPF Exporter</title></head>
			<body>
			<h1>eBPF Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Fatalf("Error sending response body: %s", err)
		}
	})

	if *debug {
		log.Printf("Debug enabled, exporting raw maps on /maps")
		http.HandleFunc("/maps", e.MapsHandler)
	}

	log.Printf("Listening on %s", *listenAddress)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatalf("Error listening on %s: %s", *listenAddress, err)
	}
}

func libbpfLogCallback(level int, msg string) {
	levelName := "unknown"
	switch level {
	case libbpfgo.LibbpfWarnLevel:
		levelName = "warn"
	case libbpfgo.LibbpfInfoLevel:
		levelName = "info"
	case libbpfgo.LibbpfDebugLevel:
		levelName = "debug"
	}

	log.Printf("libbpf [%s]: %s", levelName, msg)
}
