# xmkeep — 万能后台保活插件（整合版，xmkeep.dylib）

纯 Objective-C 写的通用后台保活插件，整合了市面两个常见插件的优点，无第三方框架依赖（无 CydiaSubstrate / theos / fishhook），TrollFools 注入任意 App 即可。

## 功能（三重保活，回前台自动停止）

| 模块 | 机制 | 前置条件 |
|---|---|---|
| 1. 后台任务无限续命（核心） | `beginBackgroundTaskWithExpirationHandler:` 到期立即重新申请，持续保有"后台任务进行中"状态 | **无需任何声明/授权**，任何 App 通用 |
| 2. 静音音频保活 | AVAudioSession Category=Playback + 运行时生成 5 秒静音 WAV 无限循环播放（volume=0） | App 声明 `UIBackgroundModes: audio` 时效果最强；未声明也能短暂保持播放状态 |
| 3. 定位保活（可选，默认关） | CLLocationManager 持续定位，后台优先级最高 | App 需 `NSLocationAlwaysUsageDescription` + `UIBackgroundModes: location` + 用户授权"始终允许" |

- 监听 `UIApplicationDidEnterBackgroundNotification` 启动保活
- 监听 `UIApplicationDidBecomeActiveNotification` 停止保活（回前台省电、避免被检测）

## 定位保活开关（默认关闭）

```objc
// 想开启定位保活：注入前先在目标 App 的 NSUserDefaults 里写入（或用调试工具设置）
[[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"xmkeep_location"];
// 关闭（默认）：
//   [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"xmkeep_location"];
```

## 使用

1. GitHub Actions 编译产物：artifact 里的 `xmkeep.dylib`
2. 用 TrollFools 注入目标 App
3. 重启 App 生效；切后台即开始保活，回前台自动停止

## 与 xmjiance 插件的关系

- `xmfjc.dylib`（xmjiance）：醒目专用（会话保护 + 越狱伪装 + 统计拦截 + 弹窗兜底 + 截图绕过）
- `xmkeep.dylib`（本插件）：**通用后台保活**，可注入任何需要后台常驻的 App
- 两个插件互不依赖，可同时注入（如醒目 = xmfjc + xmkeep）

## 说明与限制

- 后台任务续命受 iOS 系统策略限制，能显著延长后台存活时间但无法保证永久（iOS 对反复续期有惩罚）
- 音频保活的最强效果依赖 App 声明 audio 后台模式（TrollStore 可改 Info.plist 补上）
- 定位保活默认关：开启需要 App 权限声明 + 用户授权，避免强制弹授权框
- 插件本身不修改 App 的 Info.plist，后台模式声明请用 TrollStore 另改
