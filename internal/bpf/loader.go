package ebpf

type EbpfLoader interface {
	Load() error
}
