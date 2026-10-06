// xmfjc.m — 醒目 APP 抓包掉线绕过插件 v2
//
// 原理（基于 2026-10 逆向结论）：
//   1. 该 App 客户端没有"检测代理/VPN -> 踢号"的代码。
//      掉线链是：服务端风控判定异常 -> 响应带"会话失效/otherLogin"标志
//      -> 客户端 HCEventAdapter.parseResponse:root: 收到标志
//      -> 调 HCAppDelegate doLogout:（清本地账号/凭证/密码/cookie）
//      -> 下次启动 startToLogin: 发现本地凭证没了 -> 进登录页（要短信验证码）。
//   2. v2 方案：只掐掉"客户端配合清理"这一步：
//      - hook doLogout:                -> 空操作（本地会话凭证保留）
//      - hook showSessionExpiredDialog -> 空操作（不弹"会话过期"）
//      效果：被踢后凭证仍在 -> 下次打开 App 走 requestLoginBackground
//      用本地凭证静默恢复会话（不需要短信验证码）-> 无感不掉线。
//   3. 不影响：短信验证登录、7 天凭证自然过期、正常业务流程。
//      副作用：手动"退出登录"也会被吞（账号保持登录态）。
//
// 实现：纯 Objective-C runtime API（method_setImplementation），
//       不依赖 CydiaSubstrate / theos，TrollFools 注入即可。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// 吞掉 doLogout: —— 阻止清空本地会话凭证/账号
static id xmfjc_hook_doLogout(id self, SEL _cmd, ...) {
    NSLog(@"[xmfjc] doLogout: blocked (keep local session)");
    return nil;
}

// 吞掉"会话过期"弹窗
static id xmfjc_hook_showSessionExpiredDialog(id self, SEL _cmd) {
    NSLog(@"[xmfjc] showSessionExpiredDialog blocked");
    return nil;
}

__attribute__((constructor))
static void xmfjc_entry(void) {
    @autoreleasepool {
        NSLog(@"[xmfjc] loaded v2");

        Class cls = objc_getClass("HCAppDelegate");
        if (!cls) {
            NSLog(@"[xmfjc] ERROR: HCAppDelegate not found");
            return;
        }

        Method m1 = class_getInstanceMethod(cls, @selector(doLogout:));
        if (m1) {
            method_setImplementation(m1, (IMP)xmfjc_hook_doLogout);
            NSLog(@"[xmfjc] hooked doLogout: -> keep session");
        } else {
            NSLog(@"[xmfjc] ERROR: doLogout: not found on HCAppDelegate");
        }

        Method m2 = class_getInstanceMethod(cls, @selector(showSessionExpiredDialog));
        if (m2) {
            method_setImplementation(m2, (IMP)xmfjc_hook_showSessionExpiredDialog);
            NSLog(@"[xmfjc] hooked showSessionExpiredDialog -> silent");
        } else {
            NSLog(@"[xmfjc] ERROR: showSessionExpiredDialog not found on HCAppDelegate");
        }

        NSLog(@"[xmfjc] v2 done");
    }
}
