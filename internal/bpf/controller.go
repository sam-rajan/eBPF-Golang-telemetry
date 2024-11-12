package ebpf

type EbpfController interface {
	Load() error
	Unload() error
	GetValue() (int64, error)
}
