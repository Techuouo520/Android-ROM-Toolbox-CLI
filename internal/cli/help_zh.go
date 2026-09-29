package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const chineseUsageTemplate = `用法：{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [命令]{{end}}{{if gt (len .Aliases) 0}}

别名：
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

示例：
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

可用命令：{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

其他命令：{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

参数：
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

全局参数：
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

其他帮助主题：{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

使用 "{{.CommandPath}} [命令] --help" 查看命令详情。{{end}}
`

var chineseArguments = strings.NewReplacer("<unpacked-dir>", "<解包目录>", "<tree>", "<目录树>", "<image>", "<镜像>", "<file>", "<文件>", "[workspace]", "[工作目录]", "<raw.img>", "<原始镜像>", "<sparse.img>", "<稀疏镜像>", "<node>", "<节点>", "<property>", "<属性>", "<value>", "<值>", "<old>", "<旧镜像>", "<new>", "<新镜像>", "<base-image>", "<基础镜像>", "<recipe.yaml>", "<配方.yaml>", "<id>", "<编号>", "<rev>", "<版本>")

var chineseRootShort = map[string]string{
	"boot":       "解包和打包 boot,init_boot,vendor_boot 与 recovery 镜像",
	"completion": "生成指定 Shell 的自动补全脚本",
	"diff":       "按段和设备树逐项对比两个镜像",
	"dtb":        "解包,打包,查询和修改设备树二进制镜像",
	"dtbo":       "解包,打包和合并 Android DTBO 叠加镜像",
	"erofs":      "提取和构建 EROFS 分区镜像",
	"ext4":       "提取和构建 EXT4 分区镜像",
	"f2fs":       "提取和构建 F2FS 分区镜像",
	"help":       "查看命令帮助",
	"inspect":    "识别 Android 镜像并显示其结构",
	"pack":       "从解包工作目录重建变更的分区及 super 镜像",
	"payload":    "列出并提取 OTA payload 分区",
	"sparse":     "转换 Android sparse 镜像",
	"super":      "提取和组装动态分区 super 镜像",
	"unpack":     "识别格式并提取受支持的镜像",
	"vbmeta":     "查看,验证,签名和修改 Android Verified Boot 元数据",
}

func localizeChineseHelp(root *cobra.Command) {
	root.SetUsageTemplate(chineseUsageTemplate)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	for _, child := range root.Commands() {
		if short, ok := chineseRootShort[child.Name()]; ok {
			child.Short = short
		}
	}
	localizeChineseHelpFlags(root)
}

func localizeChineseHelpFlags(command *cobra.Command) {
	command.Use = chineseArguments.Replace(command.Use)
	if short, ok := chineseCommandShort[command.CommandPath()]; ok {
		command.Short = short
	}
	if long, ok := chineseCommandLong[command.CommandPath()]; ok {
		command.Long = long
	}
	command.InitDefaultHelpFlag()
	if flag := command.Flags().Lookup("help"); flag != nil {
		flag.Usage = "显示命令帮助"
	}
	command.Flags().VisitAll(func(flag *pflag.Flag) {
		if usage, ok := chineseFlagUsage[flag.Usage]; ok {
			flag.Usage = usage
		}
	})
	for _, child := range command.Commands() {
		localizeChineseHelpFlags(child)
	}
}
