// xmfjc.m — 醒目 APP 抓包不掉线 + 越狱检测伪装 插件 v3
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
//   3. v3 新增：友盟(UM)+阿里百川(ALBB)两个 SDK 的越狱检测会探测
//      Cydia.app / var/lib/apt 等路径 + 写 /private/umTest_Jailbreak 测试，
//      结果随 is_jailbroken / 设备画像上报 -> 设备被标记"越狱"。
//      方案：从源头掐文件探测 API，让越狱路径一律"不存在"、写测试一律失败，
//      两个 SDK 判定均为"未越狱"，上报为正常设备。
//   4. 不影响：短信验证登录、7 天凭证自然过期、App 正常文件读写（只拦越狱特征路径）。
//      副作用：手动"退出登录"会被吞（账号保持登录态）。
//
// 实现：纯 Objective-C runtime API（method_setImplementation），
//       无 CydiaSubstrate / theos / fishhook 依赖，TrollFools 注入即可。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// ============ 越狱特征路径判断 ============
static BOOL xmfjc_isJailbreakPath(NSString *path) {
    if (path.length == 0) return NO;
    NSString *p = [path lowercaseString];
    static NSArray<NSString *> *keys = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        keys = @[
            @"/applications/cydia.app",
            @"/private/var/lib/apt",
            @"/var/lib/apt",
            @"/etc/apt",
            @"/bin/bash",
            @"/usr/sbin/sshd",
            @"/usr/bin/ssh",
            @"/usr/libexec/sftp-server",
            @"/private/var/stash",
            @"/var/stash",
            @"/.installed_unc0ver",
            @"/.bootstrapped",
            @"/jb",
            @"/var/binpack",
            @"/library/mobilesubstrate",
            @"/usr/lib/libcycript",
            @"/usr/lib/libsubstrate",
            @"/usr/lib/substrate",
            @"umtest_jailbreak",
            @"cydia://",
            @"sileo://",
            @"filza://",
        ];
    });
    for (NSString *k in keys) {
        if ([p containsString:k]) return YES;
    }
    return NO;
}

// ============ 1. 会话保护（v2） ============
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

// ============ 2. 越狱检测伪装（v3） ============
// NSFileManager fileExistsAtPath:
static BOOL (*orig_fileExistsAtPath)(id, SEL, NSString *);
static BOOL my_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (xmfjc_isJailbreakPath(path)) {
        NSLog(@"[xmfjc] fileExistsAtPath: %@ -> NO (jailbreak path hidden)", path);
        return NO;
    }
    return orig_fileExistsAtPath(self, _cmd, path);
}

// NSFileManager fileExistsAtPath:isDirectory:
static BOOL (*orig_fileExistsAtPath_isDir)(id, SEL, NSString *, BOOL *);
static BOOL my_fileExistsAtPath_isDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (xmfjc_isJailbreakPath(path)) {
        NSLog(@"[xmfjc] fileExistsAtPath:isDirectory: %@ -> NO (jailbreak path hidden)", path);
        if (isDir) *isDir = NO;
        return NO;
    }
    return orig_fileExistsAtPath_isDir(self, _cmd, path, isDir);
}

// NSString writeToFile:atomically:encoding:error:
static BOOL (*orig_writeToFile_atomically_encoding)(id, SEL, NSString *, BOOL, NSStringEncoding, NSError **);
static BOOL my_writeToFile_atomically_encoding(id self, SEL _cmd, NSString *path, BOOL atomically, NSStringEncoding enc, NSError **err) {
    if (xmfjc_isJailbreakPath(path)) {
        NSLog(@"[xmfjc] writeToFile(encoding): %@ -> FAIL (jailbreak write blocked)", path);
        if (err) *err = [NSError errorWithDomain:@"xmfjc" code:1 userInfo:@{NSLocalizedDescriptionKey: @"write blocked"}];
        return NO;
    }
    return orig_writeToFile_atomically_encoding(self, _cmd, path, atomically, enc, err);
}

// NSString writeToFile:atomically:
static BOOL (*orig_writeToFile_atomically)(id, SEL, NSString *, BOOL);
static BOOL my_writeToFile_atomically(id self, SEL _cmd, NSString *path, BOOL atomically) {
    if (xmfjc_isJailbreakPath(path)) {
        NSLog(@"[xmfjc] writeToFile: %@ -> FAIL (jailbreak write blocked)", path);
        return NO;
    }
    return orig_writeToFile_atomically(self, _cmd, path, atomically);
}

// NSData writeToFile:atomically:
static BOOL (*orig_data_writeToFile_atomically)(id, SEL, NSString *, BOOL);
static BOOL my_data_writeToFile_atomically(id self, SEL _cmd, NSString *path, BOOL atomically) {
    if (xmfjc_isJailbreakPath(path)) {
        NSLog(@"[xmfjc] NSData writeToFile: %@ -> FAIL (jailbreak write blocked)", path);
        return NO;
    }
    return orig_data_writeToFile_atomically(self, _cmd, path, atomically);
}

// NSFileManager createFileAtPath:contents:attributes:
static BOOL (*orig_createFileAtPath)(id, SEL, NSString *, NSData *, NSDictionary *);
static BOOL my_createFileAtPath(id self, SEL _cmd, NSString *path, NSData *contents, NSDictionary *attrs) {
    if (xmfjc_isJailbreakPath(path)) {
        NSLog(@"[xmfjc] createFileAtPath: %@ -> FAIL (jailbreak write blocked)", path);
        return NO;
    }
    return orig_createFileAtPath(self, _cmd, path, contents, attrs);
}

// NSFileManager contentsOfFileAtPath:（部分 SDK 用读文件方式验证写测试）
static NSData *(*orig_contentsOfFileAtPath)(id, SEL, NSString *);
static NSData *my_contentsOfFileAtPath(id self, SEL _cmd, NSString *path) {
    if (xmfjc_isJailbreakPath(path)) {
        NSLog(@"[xmfjc] contentsOfFileAtPath: %@ -> nil (jailbreak read blocked)", path);
        return nil;
    }
    return orig_contentsOfFileAtPath(self, _cmd, path);
}

// ============ 注入入口 ============
__attribute__((constructor))
static void xmfjc_entry(void) {
    @autoreleasepool {
        NSLog(@"[xmfjc] loaded v3");

        // --- 1. 会话保护 ---
        Class appDel = objc_getClass("HCAppDelegate");
        if (appDel) {
            Method m1 = class_getInstanceMethod(appDel, @selector(doLogout:));
            if (m1) {
                method_setImplementation(m1, (IMP)xmfjc_hook_doLogout);
                NSLog(@"[xmfjc] hooked doLogout: -> keep session");
            } else {
                NSLog(@"[xmfjc] ERROR: doLogout: not found");
            }
            Method m2 = class_getInstanceMethod(appDel, @selector(showSessionExpiredDialog));
            if (m2) {
                method_setImplementation(m2, (IMP)xmfjc_hook_showSessionExpiredDialog);
                NSLog(@"[xmfjc] hooked showSessionExpiredDialog -> silent");
            } else {
                NSLog(@"[xmfjc] ERROR: showSessionExpiredDialog not found");
            }
        } else {
            NSLog(@"[xmfjc] ERROR: HCAppDelegate not found");
        }

        // --- 2. 越狱检测伪装 ---
        Class fmCls = [NSFileManager class];
        Method fm1 = class_getInstanceMethod(fmCls, @selector(fileExistsAtPath:));
        if (fm1) {
            orig_fileExistsAtPath = (void *)method_getImplementation(fm1);
            method_setImplementation(fm1, (IMP)my_fileExistsAtPath);
            NSLog(@"[xmfjc] hooked NSFileManager fileExistsAtPath:");
        }
        Method fm2 = class_getInstanceMethod(fmCls, @selector(fileExistsAtPath:isDirectory:));
        if (fm2) {
            orig_fileExistsAtPath_isDir = (void *)method_getImplementation(fm2);
            method_setImplementation(fm2, (IMP)my_fileExistsAtPath_isDir);
            NSLog(@"[xmfjc] hooked NSFileManager fileExistsAtPath:isDirectory:");
        }
        Method fm3 = class_getInstanceMethod(fmCls, @selector(createFileAtPath:contents:attributes:));
        if (fm3) {
            orig_createFileAtPath = (void *)method_getImplementation(fm3);
            method_setImplementation(fm3, (IMP)my_createFileAtPath);
            NSLog(@"[xmfjc] hooked NSFileManager createFileAtPath:contents:attributes:");
        }
        Method fm4 = class_getInstanceMethod(fmCls, @selector(contentsOfFileAtPath:));
        if (fm4) {
            orig_contentsOfFileAtPath = (void *)method_getImplementation(fm4);
            method_setImplementation(fm4, (IMP)my_contentsOfFileAtPath);
            NSLog(@"[xmfjc] hooked NSFileManager contentsOfFileAtPath:");
        }

        Class strCls = [NSString class];
        Method s1 = class_getInstanceMethod(strCls, @selector(writeToFile:atomically:encoding:error:));
        if (s1) {
            orig_writeToFile_atomically_encoding = (void *)method_getImplementation(s1);
            method_setImplementation(s1, (IMP)my_writeToFile_atomically_encoding);
            NSLog(@"[xmfjc] hooked NSString writeToFile:atomically:encoding:error:");
        }
        Method s2 = class_getInstanceMethod(strCls, @selector(writeToFile:atomically:));
        if (s2) {
            orig_writeToFile_atomically = (void *)method_getImplementation(s2);
            method_setImplementation(s2, (IMP)my_writeToFile_atomically);
            NSLog(@"[xmfjc] hooked NSString writeToFile:atomically:");
        }

        Class dataCls = [NSData class];
        Method d1 = class_getInstanceMethod(dataCls, @selector(writeToFile:atomically:));
        if (d1) {
            orig_data_writeToFile_atomically = (void *)method_getImplementation(d1);
            method_setImplementation(d1, (IMP)my_data_writeToFile_atomically);
            NSLog(@"[xmfjc] hooked NSData writeToFile:atomically:");
        }

        NSLog(@"[xmfjc] v3 done");
    }
}
