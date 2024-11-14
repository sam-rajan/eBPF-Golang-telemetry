package metric

type MetricData struct {
	Name            string
	Description     string
	Value           int64
	Unit            string
	Type            string
	ExtraAttributes map[string]string
}
