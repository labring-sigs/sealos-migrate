package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/labring-sigs/sealos-migrate/fix-kb-logs/fix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type counters struct {
	mysql     int
	mongo     int
	postgres  int
	configMap int
}

func main() {
	log.SetFlags(0)

	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig (defaults to in-cluster or ~/.kube/config)")
	dryRun := flag.Bool("dry-run", false, "Print intended changes without updating configmaps")
	flag.Parse()

	clientset, cfg, err := buildClientset(*kubeconfig)
	if err != nil {
		log.Fatalf("failed to build Kubernetes client: %v", err)
	}

	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("failed to build dynamic client: %v", err)
	}

	clusters, err := listDBClusters(dc)
	if err != nil {
		log.Fatalf("failed to list clusters: %v", err)
	}
	if len(clusters) == 0 {
		log.Printf("no apecloud-mysql/mongodb/postgresql clusters found")
		return
	}

	ctx := context.Background()
	var count counters

	configMapping := map[string]string{
		"apecloud-mysql": "mysql-mysql-consensusset-config",
		"mongodb":        "mongodb-mongodb-config",
		"postgresql":     "postgresql-postgresql-configuration",
	}

	for _, cinfo := range clusters {
		suffix, ok := configMapping[cinfo.definition]
		if !ok {
			continue
		}

		cmName := cinfo.name + "-" + suffix
		cm, err := clientset.CoreV1().ConfigMaps(cinfo.namespace).Get(ctx, cmName, metav1.GetOptions{})
		if err != nil {
			log.Printf("failed to get configmap %s/%s: %v", cinfo.namespace, cmName, err)
			continue
		}

		updated, c := processClusterConfigMaps(cinfo, []corev1.ConfigMap{*cm}, *dryRun, clientset)
		if updated {
			count.mysql += c.mysql
			count.mongo += c.mongo
			count.postgres += c.postgres
			count.configMap += c.configMap
		}
	}

	if count.configMap == 0 {
		log.Printf("no MySQL, MongoDB, or PostgreSQL configmaps needed changes")
		return
	}

	log.Printf("updated %d configmaps (MySQL: %d, MongoDB: %d, PostgreSQL: %d)", count.configMap, count.mysql, count.mongo, count.postgres)
}

func buildClientset(kubeconfig string) (*kubernetes.Clientset, *rest.Config, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, nil, err
		}
		cli, err := kubernetes.NewForConfig(cfg)
		return cli, cfg, err
	}

	// Prefer in-cluster config; fall back to local kubeconfig.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		if kubeconfigEnv := os.Getenv("KUBECONFIG"); kubeconfigEnv != "" {
			kubeconfig = kubeconfigEnv
		} else if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, nil, err
		}
	}
	cli, err := kubernetes.NewForConfig(cfg)
	return cli, cfg, err
}

type clusterInfo struct {
	name       string
	namespace  string
	definition string
}

func listDBClusters(dc dynamic.Interface) ([]clusterInfo, error) {
	gvr := schema.GroupVersionResource{
		Group:    "apps.kubeblocks.io",
		Version:  "v1alpha1",
		Resource: "clusters",
	}
	list, err := dc.Resource(gvr).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	supported := map[string]bool{
		"apecloud-mysql": true,
		"mongodb":        true,
		"postgresql":     true,
	}

	var clusters []clusterInfo
	for _, item := range list.Items {
		def := getString(item.Object, "spec", "clusterDefinitionRef")
		if !supported[def] {
			continue
		}
		clusters = append(clusters, clusterInfo{
			name:       item.GetName(),
			namespace:  item.GetNamespace(),
			definition: def,
		})
	}
	return clusters, nil
}

func getString(obj map[string]interface{}, fields ...string) string {
	curr := obj
	for i, f := range fields {
		val, ok := curr[f]
		if !ok {
			return ""
		}
		if i == len(fields)-1 {
			if s, ok := val.(string); ok {
				return s
			}
			return ""
		}
		next, ok := val.(map[string]interface{})
		if !ok {
			return ""
		}
		curr = next
	}
	return ""
}

func processClusterConfigMaps(cinfo clusterInfo, cms []corev1.ConfigMap, dryRun bool, clientset *kubernetes.Clientset) (bool, counters) {
	var count counters
	updated := false

	for i := range cms {
		cm := cms[i]
		if cm.Namespace != cinfo.namespace {
			continue
		}
		if !strings.HasPrefix(cm.Name, cinfo.name+"-") {
			continue
		}

		var changed bool
		switch cinfo.definition {
		case "apecloud-mysql":
			if raw, ok := cm.Data["my.cnf"]; ok {
				if fixed, diff, err := fix.ApplyMySQLFix(raw); err != nil {
					log.Printf("skip MySQL config %s/%s: %v", cm.Namespace, cm.Name, err)
					continue
				} else if diff {
					cm.Data["my.cnf"] = fixed
					count.mysql++
					changed = true
				}
			}
		case "mongodb":
			if raw, ok := cm.Data["mongodb.conf"]; ok {
				if fixed, diff, err := fix.ApplyMongoFix(raw); err != nil {
					log.Printf("skip MongoDB config %s/%s: %v", cm.Namespace, cm.Name, err)
					continue
				} else if diff {
					cm.Data["mongodb.conf"] = fixed
					count.mongo++
					changed = true
				}
			}
		case "postgresql":
			if raw, ok := cm.Data["postgresql.conf"]; ok {
				if fixed, diff, err := fix.ApplyPostgreSQLFix(raw); err != nil {
					log.Printf("skip PostgreSQL config %s/%s: %v", cm.Namespace, cm.Name, err)
					continue
				} else if diff {
					cm.Data["postgresql.conf"] = fixed
					count.postgres++
					changed = true
				}
			}
		}

		if !changed {
			continue
		}

		count.configMap++
		updated = true

		if dryRun {
			log.Printf("[dry-run] would update %s/%s (cluster %s, definition %s)", cm.Namespace, cm.Name, cinfo.name, cinfo.definition)
			continue
		}
		if _, err := clientset.CoreV1().ConfigMaps(cm.Namespace).Update(context.Background(), &cm, metav1.UpdateOptions{}); err != nil {
			log.Printf("failed to update configmap %s/%s: %v", cm.Namespace, cm.Name, err)
			continue
		}
		log.Printf("updated configmap %s/%s (cluster %s, definition %s)", cm.Namespace, cm.Name, cinfo.name, cinfo.definition)
	}

	return updated, count
}
