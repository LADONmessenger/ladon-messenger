//
//  IPtProxyBridge.h
//  Ladon
//
//  Objective-C wrapper for IPtProxy.xcframework
//  Needed because Swift bridging header scans before ProcessXCFramework step
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface IPtProxyBridge : NSObject

/// Initialize IPtProxy Controller
/// @param ptDir Path to pluggable transports directory
/// @param enableLogging Whether to enable PT logging
/// @param unsafeLogging Whether to enable unsafe (detailed) logging  
/// @param logLevel Log level: "ERROR", "WARN", "INFO", "DEBUG"
- (instancetype)initWithPtDir:(NSString *)ptDir
                enableLogging:(BOOL)enableLogging
               unsafeLogging:(BOOL)unsafeLogging
                    logLevel:(NSString *)logLevel;

/// Transport names as defined by IPtProxy itself.
///
/// Never hard-code these. The call sites used the string literals "Obfs4" and
/// "Snowflake", which are the names of the framework's *constants* — not
/// necessarily their values. A name the framework does not recognise makes
/// `start` fail, the port stay 0 and bridges silently switch off.
@property (class, nonatomic, readonly) NSString *obfs4Name;
@property (class, nonatomic, readonly) NSString *snowflakeName;

/// Start a pluggable transport.
/// @param transportName use `IPtProxyBridge.obfs4Name` / `.snowflakeName`
/// @return NO and sets `error` if the transport did not start. The result must
///         be handled — a discarded failure is how the transports stayed off.
- (BOOL)startTransport:(NSString *)transportName
                 error:(NSError * _Nullable * _Nullable)error;

/// Stop a pluggable transport
/// @param transportName use `IPtProxyBridge.obfs4Name` / `.snowflakeName`
- (void)stopTransport:(NSString *)transportName;

/// Get SOCKS5 port for a transport
/// @param transportName use `IPtProxyBridge.obfs4Name` / `.snowflakeName`
/// @return Port number (0 if not started)
- (NSInteger)portForTransport:(NSString *)transportName NS_SWIFT_NAME(port(forTransport:));

@end

NS_ASSUME_NONNULL_END
