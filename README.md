# xmjiance — 醒目 APP 抓包不掉线插件（xmfjc.dylib）

绕过醒目 APP（com.hollycrm.XMEMSYDCL）的代理检测：把 `isProxy` 判定恒置为 NO，
使启动环境检测认为未开代理，不触发强制登出/清会话；ProxyPin 仍可正常抓包。

- 7 天会话到期、手动退出登录等正常流程不受影响（未 hook）。
- 用法：TrollFools 注入到醒目 APP 后重启，抓包测试。
- 日志：`log stream --predicate 'process == "HollyUC"'` 或爱思助手查看控制台，检索 `[xmfjc]`。
