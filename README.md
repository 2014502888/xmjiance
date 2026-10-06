# xmjiance — 醒目 APP 抓包不掉线插件（xmfjc.dylib）

TrollStore / TrollFools 注入插件，解决"醒目 APP 在 iOS 上开代理抓包后，下次打开被要求重新登录（短信验证码）"的问题。

## 版本

- **v2（当前）**：基于逆向结论重写。
  - hook `HCAppDelegate.doLogout:` → 空操作（保留本地会话凭证/账号，不被服务端"会话失效"标志清空）
  - hook `HCAppDelegate.showSessionExpiredDialog` → 空操作（不弹"会话过期"）
  - 效果：被踢后凭证保留 → 下次打开自动用本地凭证静默恢复会话（不走短信验证码）→ 无感不掉线
- v1（废弃）：hook `isProxy` 恒返 NO —— 逆向证实该 App 无任何代码调用 `isProxy`，方案无效。

## 使用

1. GitHub Actions 编译产物：`xmfjc-dylib` artifact 里的 `xmfjc.dylib`
2. 用 TrollFools 把 `xmfjc.dylib` 注入到醒目 App
3. 重启 App 生效

## 注意

- 手动"退出登录"也会被吞（账号保持登录态）
- 7 天凭证自然到期仍会要求短信验证码（正常流程，未拦截）
- 抓包期间 App 的流量本身仍可能被服务端风控，建议抓完包关闭代理再打开 App
