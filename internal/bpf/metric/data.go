package metric

const (
	Gauge = iota
	Counter
)

type MetricData struct {
	Name            string
	Description     string
	Value           int64
	Unit            string
	Type            int
	ExtraAttributes map[string]string
}
