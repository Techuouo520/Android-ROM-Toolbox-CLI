package i18n

type Messages struct {
	RootShort     string
	VersionShort  string
	Platform      string
	LogicalCPUs   string
	Decoder       string
	CPUModel      string
	Memory        string
	MemoryUnit    string
	GPU           string
	Disk          string
	DataVolume    string
	Unavailable   string
	HardwareQuery string
	Error         string
}

func Text(language Language) Messages {
	if language == Chinese {
		return Messages{RootShort: "Android ROM 工具箱：更快,更好的解包,编辑和重建 ROM 镜像", VersionShort: "显示版本,构建及硬件信息", Platform: "平台", LogicalCPUs: "逻辑核心数", Decoder: "LZMA 解码器", CPUModel: "CPU 型号", Memory: "内存", MemoryUnit: " MB", GPU: "GPU", Disk: "硬盘", DataVolume: "数据分区", Unavailable: "不可用", HardwareQuery: "硬件查询", Error: "错误"}
	}
	return Messages{RootShort: "Android ROM Toolbox: unpack, edit and rebuild ROM images faster and better", VersionShort: "Show version, build and hardware details", Platform: "platform", LogicalCPUs: "logical_cpus", Decoder: "lzma_decoder", CPUModel: "cpu_model", Memory: "memory_mb", GPU: "GPU", Disk: "disk", DataVolume: "data volume", Unavailable: "unavailable", HardwareQuery: "hardware query", Error: "Error"}
}
