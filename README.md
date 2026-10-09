# xmjiance — 醒目 APP 抓包不掉线 + 越狱伪装 + 统计拦截 + 会话过期弹窗兜底 插件（xmfjc.dylib）

TrollStore / TrollFools 注入插件，解决"醒目 APP 在 iOS 上开代理抓包后，下次打开被要求重新登录（短信验证码）"的问题；阻止友盟 / 阿里百川 SDK 把越狱设备上报为"越狱"；拦截两个 SDK 每次启动的统计/画像上报流量。

## 版本

- **v5（当前，2026-10-09）**：
  - 在 v4 基础上新增**会话过期弹窗通用兜底**：hook `UIViewController presentViewController:animated:completion:` + `UIAlertView show`，标题/内容命中会话失效关键词（会话过期 / 登录已失效 / 重新登录 / 已过期等）一律吞掉不弹。不依赖 App 内部走哪个类、哪条路径弹"会话过期"（逆向确认弹窗不走 `showSessionExpiredDialog`，v4 拦不到）。
  - 新增**诊断提示**：每次安装/重装后首启弹一次「✓ xmfjc v5 已生效」；每次拦截到会话失效时弹「已拦截会话失效，凭证保留」。方便直接确认插件在拦截（不需要看 NSLog）。
  - 逆向确认（基于 醒目-80.ipa）：`isDeviceJailBreak` / `isExpireDateWithDate:` 均为从未被调用的死代码——掉线**不是**本地过期判断、**不是** App 主动越狱检测触发；掉线走的是服务端主动失效 + 客户端另一条弹窗路径。
- **v4**：
  - **会话保护**：hook `HCAppDelegate.doLogout:` → 空操作（保留本地会话凭证/账号，不被服务端"会话失效"标志清空）；hook `HCAppDelegate.showSessionExpiredDialog` → 空操作（不弹"会话过期"）。被踢后凭证保留 → 下次打开自动用本地凭证静默恢复会话（不走短信验证码）→ 无感不掉线。
  - **越狱检测伪装**：逆向确认越狱检测来自两个第三方 SDK —— 友盟 UM（探测 Cydia.app / var/lib/apt 等路径 + 写 `/private/umTest_Jailbreak` 写测试）和阿里百川 ALBBDeviceInfo（探测 2 个路径）。v3 从源头 hook 文件探测 API（`NSFileManager fileExistsAtPath:`/`isDirectory:`/`createFileAtPath:`/`contentsOfFileAtPath:`、`NSString writeToFile:`、`NSData writeToFile:`），命中越狱特征路径一律返回"不存在 / 写入失败" → 两个 SDK 均判定"未越狱"，`is_jailbroken` 上报为 NO。
  - **统计域名拦截（v4）**：两个 SDK 靠 `+load` 自动自启动，每次打开都会上报统计/画像（友盟 `umeng.com`/`umid`、阿里百川 `acs.m.taobao.com`/`mmstat` 等），表现为"每次打开都在读取"。hook 网络层（`NSURLSession` 4 个 dataTask 方法 + `NSURLConnection sendAsynchronousRequest:`），命中统计域名的请求 URL 替换为本地不可达地址 → 任务立即失败，与"网络不通/上报失败"效果一致，SDK 静默无感知；App 正常业务请求完全放行。
- v3：会话保护 + 越狱伪装（无统计拦截）。
- v2：仅会话保护。
- v1（废弃）：hook `isProxy` 恒返 NO —— 逆向证实该 App 无任何代码调用 `isProxy`，方案无效。

## 使用

1. GitHub Actions 编译产物：`xmfjc-dylib` artifact 里的 `xmfjc.dylib`
2. 用 TrollFools 把 `xmfjc.dylib` 注入到醒目 App
3. 重启 App 生效

## 注意

- 手动"退出登录"也会被吞（账号保持登录态）
- 7 天凭证自然到期仍会要求短信验证码（正常流程，未拦截）
- 越狱伪装只拦越狱特征路径（Cydia/apt/bash/umTest 等），App 正常文件读写不受影响
- 统计拦截只拦友盟/百川统计上报域名（umeng.com / umengcloud.com / umid / mmstat.com / acs.m.taobao.com / ut.taobao.com / cfg.m.taobao.com），App 正常业务请求完全放行；若后续 App 新增功能用到这些域名，需同步调整
- 抓包期间 App 的流量本身仍可能被服务端风控，建议抓完包关闭代理再打开 App
