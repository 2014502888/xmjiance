// xmfjc.m — 醒目 APP 代理检测绕过插件
// 原理：遍历运行时所有类，把 isProxy 方法的实现替换为恒返回 NO，
// 让 App 的启动环境检测认为"未开代理"，从而不触发强制登出/清会话。
// 不影响实际网络栈走系统代理（ProxyPin 仍可正常抓包）。
//
// 7 天会话到期、手动退出登录等正常流程不在此 hook 范围内，保持原样。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

__attribute__((constructor))
static void xmfjc_entry(void) {
    @autoreleasepool {
        NSLog(@"[xmfjc] loaded v1");

        SEL proxySel = sel_registerName("isProxy");
        int n = objc_getClassList(NULL, 0);
        Class *classes = (Class *)malloc(sizeof(Class) * n);
        n = objc_getClassList(classes, n);

        int hooked = 0;
        for (int i = 0; i < n; i++) {
            Class cls = classes[i];
            Method m = class_getInstanceMethod(cls, proxySel);
            if (!m) continue;
            const char *cn = class_getName(cls);

            // 只处理 App 自己的类（避免误伤系统框架/第三方 SDK 的业务代理逻辑）
            BOOL isAppClass = NO;
            if (cn) {
                NSString *name = [NSString stringWithUTF8String:cn];
                if ([name hasPrefix:@"HC"] || [name hasPrefix:@"Holly"] ||
                    [name hasPrefix:@"Basic"] || [name hasPrefix:@"XM"] ||
                    [name containsString:@"Login"] || [name containsString:@"Net"] ||
                    [name containsString:@"Env"] || [name containsString:@"Secur"]) {
                    isAppClass = YES;
                }
            }
            if (!isAppClass) {
                NSLog(@"[xmfjc] skip isProxy on %s", cn ? cn : "?");
                continue;
            }

            IMP newImp = imp_implementationWithBlock(^BOOL(id self) {
                return NO;  // 始终报告"未走代理"
            });
            method_setImplementation(m, newImp);
            hooked++;
            NSLog(@"[xmfjc] hooked isProxy -> NO on %s", cn ? cn : "?");
        }
        free(classes);

        NSLog(@"[xmfjc] done, hooked %d class(es)", hooked);
    }
}
