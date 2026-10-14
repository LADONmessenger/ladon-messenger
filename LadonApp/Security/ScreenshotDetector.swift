import SwiftUI
import UIKit

/// Detects and prevents screenshots for maximum security
/// FIX HIGH-06: Added secure content overlay using UITextField.isSecureTextEntry trick
class ScreenshotDetector: NSObject, ObservableObject {
    static let shared = ScreenshotDetector()
    
    @Published var screenshotDetected = false
    @Published var showScreenshotWarning = false
    
    private var screenshotNotification: NSObjectProtocol?
    /// FIX M-49: Observer token for screen capture change notification
    private var captureChangeNotification: NSObjectProtocol?
    
    /// FIX HIGH-06: Secure overlay window that prevents content from appearing in screenshots/recordings
    private var secureWindow: UIWindow?
    
    override init() {
        super.init()
        setupScreenshotDetection()
        setupScreenRecordingDetection()
    }
    
    /// FIX HIGH-06: Install screenshot-prevention overlay using UITextField.isSecureTextEntry
    /// This leverages Apple's DRM layer to hide content from screen capture APIs.
    func installSecureOverlay(in scene: UIWindowScene) {
        let window = UIWindow(windowScene: scene)
        window.isHidden = false
        window.isUserInteractionEnabled = false
        window.windowLevel = .normal + 1
        window.backgroundColor = .clear
        
        let field = UITextField()
        field.isSecureTextEntry = true
        field.isUserInteractionEnabled = false
        window.addSubview(field)
        field.centerYAnchor.constraint(equalTo: window.centerYAnchor).isActive = true
        field.centerXAnchor.constraint(equalTo: window.centerXAnchor).isActive = true
        
        // Make the secure layer cover the entire window
        if let secureLayer = field.layer.sublayers?.first {
            // FIX MED-09: UIScreen.main deprecated in iOS 16+ — use window bounds instead
            secureLayer.frame = window.bounds
            window.layer.addSublayer(secureLayer)
        }
        
        self.secureWindow = window
    }
    
    /// Detect screenshots using UIPasteboard (works reliably on iOS 13+)
    private func setupScreenshotDetection() {
        screenshotNotification = NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.handleScreenshotDetected()
        }
    }
    
    /// Detect screen recording using UIScreen
    /// FIX SM-M6: Store timer reference as property so it can be invalidated in deinit
    private var screenRecordingTimer: Timer?
    
    private func setupScreenRecordingDetection() {
        // FIX M-49: Use notification-based detection for immediate response to capture state changes.
        // UIScreen.capturedDidChangeNotification fires instantly, while the polling timer
        // provides a safety net for edge cases.
        captureChangeNotification = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            let isCaptured = (UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .first?.windows.first?.screen.isCaptured) ?? false
            if isCaptured {
                self?.handleScreenRecordingDetected()
            }
        }
        
        // Polling fallback: monitor screen recording status periodically
        let timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            // FIX MED-09: UIScreen.main deprecated in iOS 16+ — use scene-based check
            let isCaptured = (UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .first?.windows.first?.screen.isCaptured) ?? false
            if isCaptured {
                self?.handleScreenRecordingDetected()
            }
        }
        self.screenRecordingTimer = timer
    }
    
    private func handleScreenshotDetected() {
        #if DEBUG
        print("[ScreenshotDetector] 🚨 SCREENSHOT DETECTED")
        #endif
        
        DispatchQueue.main.async {
            self.screenshotDetected = true
            self.showScreenshotWarning = true
            
            // Trigger security alert
            self.showSecurityAlert(type: .screenshot)
            
            // Log the incident
            SecurityUtils.shared.logSecurityEvent("screenshot_detected", severity: .high)
        }
        
        // Auto-dismiss warning after 3 seconds
        // FIX LOW-07: Also reset screenshotDetected flag (was never reset, blocking UI)
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
            self.showScreenshotWarning = false
            self.screenshotDetected = false
        }
    }
    
    private func handleScreenRecordingDetected() {
        #if DEBUG
        print("[ScreenshotDetector] 🚨 SCREEN RECORDING DETECTED")
        #endif
        
        DispatchQueue.main.async {
            self.showSecurityAlert(type: .screenRecording)
            SecurityUtils.shared.logSecurityEvent("screen_recording_detected", severity: .critical)
        }
    }
    
    private func showSecurityAlert(type: AlertType) {
        DispatchQueue.main.async {
            // This will be handled by the view that observes this object
            #if DEBUG
            print("[ScreenshotDetector] 🔒 Security Alert: \(type.message)")
            #endif
        }
    }
    
    deinit {
        if let notification = screenshotNotification {
            NotificationCenter.default.removeObserver(notification)
        }
        // FIX M-49: Remove capture change observer
        if let captureNotification = captureChangeNotification {
            NotificationCenter.default.removeObserver(captureNotification)
        }
        // FIX SM-M6: Invalidate screen recording timer to prevent leak
        screenRecordingTimer?.invalidate()
        screenRecordingTimer = nil
    }
}

// MARK: - Alert Type Definition
extension ScreenshotDetector {
    enum AlertType {
        case screenshot
        case screenRecording
        
        var title: String {
            switch self {
            case .screenshot:
                return "⚠️ Screenshot Detected"
            case .screenRecording:
                return "🚨 Screen Recording Detected"
            }
        }
        
        var message: String {
            switch self {
            case .screenshot:
                return LanguageManager.localized("Screenshots of this conversation are not permitted. This action has been logged for security purposes.\n\nLADON messenger enforces maximum privacy - sensitive messages should never be captured or shared.")
            case .screenRecording:
                return LanguageManager.localized("Screen recording is not permitted while LADON messenger is active. This constitutes a severe security violation.\n\nPlease disable screen recording immediately.")
            }
        }
    }
}
