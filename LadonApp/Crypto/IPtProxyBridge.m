//
//  IPtProxyBridge.m
//  Ladon
//
//  Objective-C wrapper for IPtProxy.xcframework
//

#import "IPtProxyBridge.h"

// Transport names exported by IPtProxy. Declared here rather than importing the
// framework header, for the same reason IPtProxyController is: the Swift
// bridging header is scanned before the ProcessXCFramework step. Linking
// resolves these against the framework's own symbols, so the values are always
// whatever IPtProxy defines — they cannot drift out of sync with a literal.
FOUNDATION_EXPORT NSString * _Nonnull const IPtProxyObfs4;
FOUNDATION_EXPORT NSString * _Nonnull const IPtProxySnowflake;

@interface IPtProxyController : NSObject
- (instancetype)init:(NSString *)stateDir
     enableLogging:(BOOL)enableLogging
    unsafeLogging:(BOOL)unsafeLogging
        logLevel:(NSString *)logLevel
    transportEvents:(id _Nullable)transportEvents;
- (BOOL)start:(NSString *)methodName proxy:(NSString * _Nullable)proxy error:(NSError * _Nullable * _Nullable)error;
- (void)stop:(NSString *)methodName;
- (long)port:(NSString *)methodName;
@end

@interface IPtProxyBridge ()
@property (nonatomic, strong) IPtProxyController *controller;
@end

@implementation IPtProxyBridge

- (instancetype)initWithPtDir:(NSString *)ptDir
                enableLogging:(BOOL)enableLogging
               unsafeLogging:(BOOL)unsafeLogging
                    logLevel:(NSString *)logLevel {
    self = [super init];
    if (self) {
        _controller = [[IPtProxyController alloc] init:ptDir
                         enableLogging:enableLogging
                        unsafeLogging:unsafeLogging
                             logLevel:logLevel
                           transportEvents:nil];
    }
    return self;
}

+ (NSString *)obfs4Name {
    return IPtProxyObfs4;
}

+ (NSString *)snowflakeName {
    return IPtProxySnowflake;
}

- (BOOL)startTransport:(NSString *)transportName
                 error:(NSError * _Nullable * _Nullable)error {
    if (!self.controller) {
        if (error) {
            *error = [NSError errorWithDomain:@"app.ladon.iptproxy"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey:
                                                    @"IPtProxy controller not initialised"}];
        }
        return NO;
    }
    return [self.controller start:transportName proxy:nil error:error];
}

- (void)stopTransport:(NSString *)transportName {
    if (self.controller) {
        [self.controller stop:transportName];
    }
}

- (NSInteger)portForTransport:(NSString *)transportName {
    if (self.controller) {
        return [self.controller port:transportName];
    }
    return 0;
}

@end
