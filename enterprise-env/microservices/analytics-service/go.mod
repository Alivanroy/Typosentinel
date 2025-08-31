module analytics-service

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/go-redis/redis/v8 v8.11.5
	github.com/lib/pq v1.10.9
	gorm.io/driver/postgres v1.5.4
	gorm.io/gorm v1.25.5
	go.mongodb.org/mongo-driver v1.13.1
	github.com/elastic/go-elasticsearch/v8 v8.11.1
	github.com/influxdata/influxdb-client-go/v2 v2.13.0
	github.com/prometheus/client_golang v1.17.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/viper v1.17.0
	go.uber.org/zap v1.26.0
	github.com/segmentio/kafka-go v0.4.47
	github.com/nats-io/nats.go v1.31.0
	github.com/apache/arrow/go/v14 v14.0.2
	github.com/apache/pulsar-client-go v0.12.1
	github.com/ClickHouse/clickhouse-go/v2 v2.15.0
	github.com/snowflakedb/gosnowflake v1.7.1
	github.com/aws/aws-sdk-go v1.48.6
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	github.com/googleapis/google-cloud-go v0.112.0
	github.com/google/uuid v1.4.0
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/gorilla/websocket v1.5.1
	github.com/robfig/cron/v3 v3.0.1
	github.com/shopspring/decimal v1.3.1
	github.com/stretchr/testify v1.8.4
	github.com/tidwall/gjson v1.17.0
	github.com/tidwall/sjson v1.2.5
	github.com/valyala/fastjson v1.6.4
	github.com/go-playground/validator/v10 v10.16.0
	github.com/opentracing/opentracing-go v1.2.0
	github.com/jaegertracing/jaeger-client-go v2.30.0+incompatible
	github.com/hashicorp/consul/api v1.25.1
	github.com/hashicorp/vault/api v1.10.0
	github.com/etcd-io/etcd/clientv3 v3.5.10
	k8s.io/client-go v0.28.4
	github.com/docker/docker v24.0.7+incompatible
	github.com/containerd/containerd v1.7.8
	github.com/grafana/grafana-api-golang-client v0.25.0
	github.com/prometheus/prometheus v0.48.0
	github.com/VictoriaMetrics/VictoriaMetrics v1.95.1
	github.com/dgraph-io/dgo/v230 v230.0.1
	github.com/neo4j/neo4j-go-driver/v5 v5.14.0
	github.com/arangodb/go-driver v1.6.1
	github.com/gocql/gocql v1.6.0
	github.com/scylladb/gocqlx/v2 v2.8.0
	github.com/olivere/elastic/v7 v7.0.32
	github.com/opensearch-project/opensearch-go/v2 v2.3.0
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358
	github.com/chromedp/cdproto v0.0.0-20231205062650-00455a960d61
	github.com/chromedp/chromedp v0.9.3
)

require (
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.4 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.0.8 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	yaml.v3 v3.0.1 // indirect
)