// xmkeep.m — 万能后台保活插件（整合版）v1
//
// 整合 BackRun 万能常驻后台 + 保持后台 BackgroundProcess 两个插件的优点：
//   1. 后台任务无限续命（BackRun 核心）
//      beginBackgroundTaskWithExpirationHandler: 到期立即重新申请，
//      让 App 在切后台后持续保有"进行中的后台任务"状态，尽量不被挂起。
//      —— 任何 App 都可用，无需 Info.plist 声明后台模式、无需用户授权。
//   2. 静音音频保活（两个插件都有）
//      AVAudioSession Category=Playback + 运行时生成的静音 WAV 无限循环播放。
//      App 若声明了 UIBackgroundModes: audio，后台播放不被暂停，保活最强；
//      未声明时也能让 App 短暂保持"播放中"状态（效果随系统策略递减）。
//   3. 可选定位保活（BackgroundProcess 增强，默认关闭）
//      CLLocationManager 持续定位，iOS 对定位中的 App 后台优先级最高。
//      ⚠️ 需要：App Info.plist 加 NSLocationAlwaysUsageDescription + 
//      UIBackgroundModes: location；用户授权"始终允许"。
//      默认不开（避免弹授权框），要开启：NSUserDefaults 设 xmkeep_location=YES。
//   4. 回前台自动停止全部保活（省电、避免被 App 检测）。
//
// 纯 Objective-C runtime + 系统框架（UIKit/AVFoundation/CoreLocation），
// 无 CydiaSubstrate / theos / fishhook 依赖，TrollFools 注入即可。
// 体积约 20-40KB（对比 BackRun 579KB 内嵌 Swift runtime，小一个数量级）。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreLocation/CoreLocation.h>
#import <objc/runtime.h>

// ============ 1. 后台任务无限续命 ============
static UIBackgroundTaskIdentifier xmkeep_bgTask = UIBackgroundTaskInvalid;

static void xmkeep_renewBackgroundTask(void) {
    // 上一任务结束掉，重新申请（iOS 对反复续命有策略限制，尽力延长）
    if (xmkeep_bgTask != UIBackgroundTaskInvalid) {
        [[UIApplication sharedApplication] endBackgroundTask:xmkeep_bgTask];
        xmkeep_bgTask = UIBackgroundTaskInvalid;
    }
    xmkeep_bgTask = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
        NSLog(@"[xmkeep] bg task expired, renewing...");
        xmkeep_renewBackgroundTask();
    }];
    NSLog(@"[xmkeep] bg task renewed: %lu", (unsigned long)xmkeep_bgTask);
}

// ============ 2. 静音音频保活 ============
// 运行时生成 N 秒 16-bit 单声道静音 WAV（无需打包音频文件）
static NSData *xmkeep_makeSilentWAV(int seconds, int sampleRate) {
    int dataLen = seconds * sampleRate * 2; // 16-bit mono
    NSMutableData *d = [NSMutableData dataWithCapacity:44 + dataLen];
    // RIFF header (little-endian)
    uint32_t chunkSize = 36 + (uint32_t)dataLen;
    uint16_t fmt = 1;          // PCM
    uint16_t ch = 1;           // mono
    uint32_t byteRate = (uint32_t)(sampleRate * 2);
    uint16_t align = 2;
    uint16_t bits = 16;
    [d appendBytes:"RIFF" length:4];
    [d appendBytes:&chunkSize length:4];
    [d appendBytes:"WAVE" length:4];
    [d appendBytes:"fmt " length:4];
    uint32_t fmtSize = 16;
    [d appendBytes:&fmtSize length:4];
    [d appendBytes:&fmt length:2];
    [d appendBytes:&ch length:2];
    [d appendBytes:&sampleRate length:4];
    [d appendBytes:&byteRate length:4];
    [d appendBytes:&align length:2];
    [d appendBytes:&bits length:2];
    [d appendBytes:"data" length:4];
    [d appendBytes:&dataLen length:4];
    // 静音 PCM（全零）
    void *zeros = calloc(dataLen, 1);
    [d appendBytes:zeros length:dataLen];
    free(zeros);
    return d;
}

static AVAudioPlayer *xmkeep_player;

static void xmkeep_startAudioKeepAlive(void) {
    if (xmkeep_player && xmkeep_player.playing) return;
    AVAudioSession *session = [AVAudioSession sharedInstance];
    [session setCategory:AVAudioSessionCategoryPlayback error:nil];
    [session setActive:YES error:nil];
    if (!xmkeep_player) {
        NSData *wav = xmkeep_makeSilentWAV(5, 8000);
        xmkeep_player = [[AVAudioPlayer alloc] initWithData:wav error:nil];
        xmkeep_player.numberOfLoops = -1; // 无限循环
        xmkeep_player.volume = 0.0f;      // 静音
    }
    [xmkeep_player play];
    NSLog(@"[xmkeep] silent audio keep-alive started");
}

static void xmkeep_stopAudioKeepAlive(void) {
    if (xmkeep_player) {
        [xmkeep_player stop];
        NSLog(@"[xmkeep] silent audio keep-alive stopped");
    }
}

// ============ 3. 可选定位保活（默认关） ============
static CLLocationManager *xmkeep_locMgr;

static void xmkeep_startLocationKeepAlive(void) {
    // 默认关：需要 App 声明 NSLocationAlwaysUsageDescription + location 后台模式
    if (![[NSUserDefaults standardUserDefaults] boolForKey:@"xmkeep_location"]) {
        NSLog(@"[xmkeep] location keep-alive disabled (set NSUserDefaults xmkeep_location=YES to enable)");
        return;
    }
    if (xmkeep_locMgr) return;
    xmkeep_locMgr = [CLLocationManager new];
    if ([xmkeep_locMgr respondsToSelector:@selector(requestAlwaysAuthorization)]) {
        [xmkeep_locMgr requestAlwaysAuthorization];
    }
    [xmkeep_locMgr startUpdatingLocation];
    NSLog(@"[xmkeep] location keep-alive started");
}

static void xmkeep_stopLocationKeepAlive(void) {
    if (xmkeep_locMgr) {
        [xmkeep_locMgr stopUpdatingLocation];
        xmkeep_locMgr = nil;
        NSLog(@"[xmkeep] location keep-alive stopped");
    }
}

// ============ 通知处理 ============
static void xmkeep_onEnterBackground(NSNotification *n) {
    NSLog(@"[xmkeep] did enter background, starting keep-alive");
    xmkeep_renewBackgroundTask();     // 1. 后台任务续命
    xmkeep_startAudioKeepAlive();     // 2. 静音音频保活
    xmkeep_startLocationKeepAlive();  // 3. 可选定位保活
}

static void xmkeep_onBecomeActive(NSNotification *n) {
    NSLog(@"[xmkeep] became active, stopping keep-alive");
    xmkeep_stopAudioKeepAlive();
    xmkeep_stopLocationKeepAlive();
    if (xmkeep_bgTask != UIBackgroundTaskInvalid) {
        [[UIApplication sharedApplication] endBackgroundTask:xmkeep_bgTask];
        xmkeep_bgTask = UIBackgroundTaskInvalid;
    }
}

// ============ 注入入口 ============
__attribute__((constructor))
static void xmkeep_entry(void) {
    @autoreleasepool {
        NSLog(@"[xmkeep] loaded v1");
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        [nc addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil queue:nil usingBlock:^(NSNotification *n) {
            xmkeep_onEnterBackground(n);
        }];
        [nc addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:nil usingBlock:^(NSNotification *n) {
            xmkeep_onBecomeActive(n);
        }];
        NSLog(@"[xmkeep] v1 done (bg task + silent audio + optional location)");
    }
}
